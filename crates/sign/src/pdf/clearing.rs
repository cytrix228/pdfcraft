//! Clearing a signature (Acrobat: Clear Signature). Only its signer may: the digital ID that
//! made it has to sign a fresh challenge that the signature's certificate verifies. A `.p12`
//! opens only with its password, so for a file that is where the password is confirmed; a key
//! store asks for its own PIN or password when it needs one.
//!
//! This keeps the user from clearing someone else's signature by mistake. It is not a lock:
//! anyone with the file can cut its last revisions off.

use super::listing::{Field, is_document_timestamp, nums, sig_fields};
use super::validate::{is_doc_timestamp, unhex};
use super::{Arc, Certificate, Dict, Document, HashSet, ObjRef, Object, SaveOptions, SignError, SignedData};
use crate::keys::{PublicKey, Scheme};
use crate::pkcs12::DigitalId;
use pdfcraft_cos::XrefEntry;

/// What [`clear`] wrote.
#[derive(Clone, Debug)]
pub struct Cleared {
    /// The file with the signature cleared.
    pub bytes: Arc<Vec<u8>>,
    /// Signing added the field (a signature drawn on the page), so it went with the signature.
    /// A field that was there before signing stays, empty, with the appearance it had then.
    pub field_removed: bool,
    /// Nothing else changed after signing: `bytes` is the file as it was before, byte for byte.
    pub restored: bool,
}

fn refuse(message: String) -> SignError {
    SignError::Pdf(message)
}

/// Clear the signature in `field` as its signer, proven with `id` (see the module notes). `date`
/// is the new `/ModDate`, stamped when the result needs an update of its own.
///
/// The file is cut back to the revision before the one the signature was written in, and the
/// document as it is now, without the signature, is written on top as one incremental update. No
/// byte of the signature (its certificates, its signed attributes) is left in the file, and the
/// signatures made before it keep the bytes they signed. A signature that a later one covers is
/// refused: clearing it would change what the later signer signed, so that one is cleared first.
pub fn clear(doc: &Document, field: &str, id: &DigitalId, date: Option<&str>) -> Result<Cleared, SignError> {
    // A pending security change would make the update a full rewrite that also applies it.
    if doc.encryption_changed() {
        return Err(refuse("save the document's new security settings before clearing a signature".into()));
    }
    let fields = sig_fields(doc);
    let f = fields.iter().find(|f| f.name == field).ok_or_else(|| refuse(format!("there is no signature field {field:?}")))?;
    let v = f.signature(doc).ok_or_else(|| refuse(format!("the field {field:?} is not signed")))?;
    if is_doc_timestamp(&v) {
        return Err(refuse(format!("the field {field:?} holds a document timestamp, which has no signer to confirm")));
    }
    let bytes = doc.bytes();
    let (gap_start, covered, contents) = signed_range(doc, &v, bytes).ok_or_else(|| {
        refuse(format!("the byte range of the signature in {field:?} doesn't match the file, so the revision that added it can't be found"))
    })?;
    let signer = signer_certificate(doc, &v, &contents)
        .ok_or_else(|| refuse(format!("the signature in {field:?} carries no certificate PdfCraft can read, so its signer can't be confirmed")))?;

    // The revision the signature was written in starts after the last one that ends before its
    // `/Contents`; that earlier revision is what the file is cut back to.
    let ends = doc.revision_ends();
    let prev_end = ends.iter().copied().filter(|e| *e <= gap_start).max();
    let v_ref = f.dict.get(b"V").and_then(Object::as_ref);
    let others = other_signatures(doc, &fields, field);
    for other in &others {
        let Some((_, end, _)) = signed_range(doc, other, bytes) else { continue };
        if end > covered {
            return Err(refuse(format!("a later signature covers the one in {field:?}: clear that one first")));
        }
        if end > prev_end.unwrap_or(0) {
            return Err(refuse(if ends.is_empty() {
                format!(
                    "the file's revisions can't be read (it was repaired), so the signature in {field:?} can't be cleared without breaking the others"
                )
            } else {
                format!("another signature was added in the same revision as the one in {field:?}, so it can't be cleared on its own")
            }));
        }
    }
    let base = match prev_end {
        Some(end) => {
            let prefix = bytes.get(..end).ok_or_else(|| refuse("the file is shorter than its revisions".into()))?;
            Some(doc.open_with_same_credentials(Arc::new(prefix.to_vec()))?)
        }
        None => None,
    };
    let field_removed = base.as_ref().is_some_and(|b| !sig_fields(b).iter().any(|bf| bf.name == field));
    let root = doc.root().ok_or_else(|| refuse("the document has no catalog".into()))?;
    let certifies = v_ref.is_some() && perms_docmdp(doc, root) == v_ref;
    check_permissions(doc, field_removed, certifies)?;
    let fr = f.r.ok_or_else(|| refuse(format!("the field {field:?} is not an indirect object")))?;
    if f.widgets.iter().any(|(w, _)| w.is_none()) {
        return Err(refuse(format!("a widget of the field {field:?} is not an indirect object")));
    }

    // Only now, with nothing left to refuse: the digital ID proves it made the signature.
    prove_signer(id, &signer)?;

    let mut out = doc.clone();
    if field_removed {
        remove_field(&mut out, base.as_ref(), root, f, fr)?;
    } else {
        out.update_dict(fr, |d| {
            d.remove(b"V");
        })?;
        for wr in f.widgets.iter().filter_map(|(w, _)| *w) {
            // The appearance the widget had before signing; none if it had none then.
            let before =
                base.as_ref().and_then(|b| b.get(wr).as_dict().filter(|w| w.name(b"Subtype") == Some(b"Widget")).and_then(|w| w.get(b"AP").cloned()));
            out.update_dict(wr, |w| match before {
                Some(ap) => w.set(b"AP".to_vec(), ap),
                None => {
                    w.remove(b"AP");
                }
            })?;
        }
    }
    if let Some(vr) = v_ref {
        out.free(vr);
    }
    if certifies {
        // The certification goes with its signature.
        edit_at(&mut out, root, &[b"Perms"], |p| {
            p.remove(b"DocMDP");
        })?;
        if dict_at(&out, root, &[b"Perms"]).is_some_and(|p| p.is_empty()) {
            out.update_dict(root, |c| {
                c.remove(b"Perms");
            })?;
        }
    }
    drop_vri(&mut out, root, &contents)?;
    sig_flags(&mut out, root, base.as_ref(), !others.is_empty())?;
    if let Some(b) = &base {
        restore_info(&mut out, b);
    }

    let save = SaveOptions { mod_date: date.map(str::to_string), ..SaveOptions::default() };
    let (bytes, restored) = match base {
        Some(mut b) => {
            let before = b.clone();
            b.overlay_changes_from(&out)?;
            // What the signature brought and nothing refers to any more (its appearance) is left
            // out. A number freed that the earlier file never had changes nothing in it, and
            // neither does an object written again as it was there.
            b.free_unlinked_additions();
            let live = b.object_numbers();
            let changed = b.modified_objects().into_iter().any(|n| {
                let had = !matches!(before.xref_entry(n), None | Some(XrefEntry::Free { .. }));
                if live.binary_search(&n).is_err() {
                    return had;
                }
                !had || !same(&b.get(ObjRef::new(n, b.generation(n))), &before.get(ObjRef::new(n, before.generation(n))))
            });
            if changed { (Arc::new(pdfcraft_cos::write_incremental(&b, &save)?), false) } else { (b.bytes().clone(), true) }
        }
        // The signature is in the file's first revision: nothing before it to keep.
        None => (Arc::new(pdfcraft_cos::write_full(&out, &save)?), false),
    };
    Ok(Cleared { bytes, field_removed, restored })
}

/// `(start of the /Contents gap, end of the signed bytes, the /Contents bytes)` of signature
/// value `v`, checked against `bytes` as validation checks them.
fn signed_range(doc: &Document, v: &Dict, bytes: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    let br = nums(doc, v, b"ByteRange")?;
    let &[o0, l0, o1, l1] = br.as_slice() else { return None };
    if [o0, l0, o1, l1].iter().any(|x| !x.is_finite() || *x < 0.0) {
        return None;
    }
    // Saturating casts of finite, non-negative numbers.
    let [o0, l0, o1, l1] = [o0 as usize, l0 as usize, o1 as usize, l1 as usize];
    let end = o1.checked_add(l1)?;
    if o0 != 0 || o1 < l0.saturating_add(2) || end > bytes.len() {
        return None;
    }
    let gap = bytes.get(l0..o1)?;
    let hex = gap.strip_prefix(b"<")?.strip_suffix(b">")?;
    Some((l0, end, unhex(hex)?))
}

/// The certificate of the signer of `v`, whose `/Contents` is `contents`.
fn signer_certificate(doc: &Document, v: &Dict, contents: &[u8]) -> Option<Certificate> {
    if v.name(b"SubFilter") == Some(b"adbe.x509.rsa_sha1") {
        // `/Cert` holds the signer's certificate first, as validation reads it.
        let raw: Vec<Vec<u8>> = match v.get(b"Cert").map(|c| doc.resolve(c)).as_deref() {
            Some(Object::Array(a)) => a.iter().filter_map(|c| doc.resolve(c).as_string().map(|s| s.bytes.clone())).collect(),
            Some(Object::String(s)) => vec![s.bytes.clone()],
            _ => Vec::new(),
        };
        return raw.iter().find_map(|c| Certificate::parse(c).ok());
    }
    SignedData::parse(contents).ok()?.signer_certificate().cloned()
}

/// Every other signature value in the file: the other fields' and standalone document timestamps.
fn other_signatures(doc: &Document, fields: &[Field], field: &str) -> Vec<Dict> {
    let values: HashSet<ObjRef> = fields.iter().filter_map(|f| f.dict.get(b"V").and_then(Object::as_ref)).collect();
    let mut out: Vec<Dict> = fields.iter().filter(|f| f.name != field).filter_map(|f| f.signature(doc)).collect();
    for (r, o) in doc.scan_objects() {
        if !values.contains(&r)
            && is_document_timestamp(&o)
            && let Some(d) = o.as_dict()
        {
            out.push(d.clone());
        }
    }
    out
}

/// What an encrypted document opened with its user password allows (ISO 32000-2 Table 22), as
/// for signing: emptying a signature field is filling in a form field, taking away a field
/// signing added changes annotations and the document, and so does removing a certification.
fn check_permissions(doc: &Document, field_removed: bool, certifies: bool) -> Result<(), SignError> {
    let Some(p) = doc.permissions() else { return Ok(()) };
    let refused = |what: &str| {
        Err(refuse(format!("the document's security settings don't allow {what}; open it with the permissions password to clear the signature")))
    };
    if !p.fill_forms() {
        return refused("filling in form fields or signing");
    }
    if field_removed && !(p.annotate() && p.modify()) {
        return refused("removing the signature field signing added");
    }
    if certifies && !p.modify() {
        return refused("removing a certification");
    }
    Ok(())
}

/// Check that `id` holds the private key of `signer`'s certificate: it signs a fresh challenge,
/// which that certificate's key must verify. A certificate alone proves nothing, since anyone can
/// put a copy of it in a digital ID of their own.
fn prove_signer(id: &DigitalId, signer: &Certificate) -> Result<(), SignError> {
    let not_signer = || refuse("this digital ID did not make the signature: only its signer can clear it".into());
    // Asked first, so a key store doesn't prompt for the wrong ID.
    if id.certificate.public_key != signer.public_key {
        return Err(not_signer());
    }
    let scheme = match signer.public_key {
        PublicKey::Rsa { .. } => Scheme::RsaPkcs1,
        _ => Scheme::Ecdsa,
    };
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| SignError::Crypto(format!("no randomness: {e}")))?;
    let message = [&b"PdfCraft: clear a signature "[..], &challenge].concat();
    let alg = id.key.preferred_digest();
    let signature = id.key.sign(alg, &message)?;
    if signer.public_key.verify(scheme, alg, &alg.digest(&[&message]), &signature)? { Ok(()) } else { Err(not_signer()) }
}

/// The signature value the catalog's `/Perms /DocMDP` names.
fn perms_docmdp(doc: &Document, root: ObjRef) -> Option<ObjRef> {
    dict_at(doc, root, &[b"Perms"]).and_then(|p| p.reference(b"DocMDP"))
}

/// The dictionary at `path` from the object `holder`, through references.
fn dict_at(doc: &Document, holder: ObjRef, path: &[&[u8]]) -> Option<Dict> {
    let mut d = doc.get(holder).as_dict().cloned()?;
    for key in path {
        d = doc.resolve(d.get(key)?).as_dict().cloned()?;
    }
    Some(d)
}

/// Edit the dictionary at `path` from the object `holder` where it is written: in the last
/// object on the way, inline or as an object of its own. Nothing when there is none.
fn edit_at(doc: &mut Document, holder: ObjRef, path: &[&[u8]], f: impl FnOnce(&mut Dict)) -> Result<(), SignError> {
    let mut at = holder;
    let mut inline: Vec<&[u8]> = Vec::new();
    let Some(mut d) = doc.get(holder).as_dict().cloned() else { return Ok(()) };
    for &key in path {
        d = match d.get(key) {
            Some(Object::Ref(r)) => {
                at = *r;
                inline.clear();
                let Some(next) = doc.get(*r).as_dict().cloned() else { return Ok(()) };
                next
            }
            Some(Object::Dict(next)) => {
                inline.push(key);
                next.clone()
            }
            _ => return Ok(()),
        };
    }
    doc.update_dict(at, |d| {
        let mut target = d;
        for &key in &inline {
            match target.get_mut(key) {
                Some(Object::Dict(next)) => target = next,
                _ => return,
            }
        }
        f(target);
    })?;
    Ok(())
}

/// `array` without references to `gone`; `None` when it holds none of them.
fn without(array: &[Object], gone: &HashSet<ObjRef>) -> Option<Vec<Object>> {
    let hit = |o: &Object| o.as_ref().is_some_and(|r| gone.contains(&r));
    array.iter().any(hit).then(|| array.iter().filter(|o| !hit(o)).cloned().collect())
}

/// Take references to `gone` out of the array under `key` of the dictionary at `path` from
/// `holder`: an array of its own is rewritten where it is, one written in the dictionary there
/// (and taken out, key and all, when it ends up empty and `drop_empty`).
fn drop_refs(doc: &mut Document, holder: ObjRef, path: &[&[u8]], key: &[u8], gone: &HashSet<ObjRef>, drop_empty: bool) -> Result<(), SignError> {
    let Some(value) = dict_at(doc, holder, path).and_then(|d| d.get(key).cloned()) else { return Ok(()) };
    match value {
        Object::Ref(r) => {
            if let Some(kept) = doc.get(r).as_array().and_then(|a| without(a, gone)) {
                doc.set(r, Object::Array(kept));
            }
        }
        Object::Array(a) => {
            if let Some(kept) = without(&a, gone) {
                edit_at(doc, holder, path, |d| {
                    if kept.is_empty() && drop_empty {
                        d.remove(key);
                    } else {
                        d.set(key.to_vec(), Object::Array(kept));
                    }
                })?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Take a field that signing added off its pages and out of the form. A page that had no
/// annotations before signing (in `base`) is left without an `/Annots` again.
fn remove_field(doc: &mut Document, base: Option<&Document>, root: ObjRef, f: &Field, fr: ObjRef) -> Result<(), SignError> {
    let gone: HashSet<ObjRef> = f.widgets.iter().filter_map(|(w, _)| *w).chain([fr]).collect();
    for page in pdfcraft_annot::page_refs(doc).map_err(|e| SignError::Pdf(e.to_string()))? {
        let had_none = base.is_some_and(|b| b.get(page).as_dict().is_some_and(|p| p.name(b"Type") == Some(b"Page") && !p.contains(b"Annots")));
        drop_refs(doc, page, &[], b"Annots", &gone, had_none)?;
    }
    match f.dict.reference(b"Parent") {
        Some(parent) => drop_refs(doc, parent, &[], b"Kids", &gone, false)?,
        None => drop_refs(doc, root, &[b"AcroForm"], b"Fields", &gone, false)?,
    }
    for r in gone {
        doc.free(r);
    }
    Ok(())
}

/// Remove the signature's entry from the security store's `/VRI` (keyed by the SHA-1 of its
/// `/Contents`). The certificates and revocation data stay: other signatures may rely on them.
fn drop_vri(doc: &mut Document, root: ObjRef, contents: &[u8]) -> Result<(), SignError> {
    let key = crate::dss::vri_key(contents);
    if dict_at(doc, root, &[b"DSS", b"VRI"]).is_none_or(|vri| !vri.contains(key.as_bytes())) {
        return Ok(());
    }
    edit_at(doc, root, &[b"DSS", b"VRI"], |vri| {
        vri.remove(key.as_bytes());
    })?;
    if dict_at(doc, root, &[b"DSS", b"VRI"]).is_some_and(|vri| vri.is_empty()) {
        edit_at(doc, root, &[b"DSS"], |dss| {
            dss.remove(b"VRI");
        })?;
    }
    Ok(())
}

/// The form's `/SigFlags` after clearing. With an earlier revision to go back to they are as they
/// were then, and a form that signing added goes too once it is empty again. In a file's first
/// revision they follow what is left: signature fields (1) and signatures (2, append only).
fn sig_flags(doc: &mut Document, root: ObjRef, base: Option<&Document>, signatures_left: bool) -> Result<(), SignError> {
    let Some(form) = dict_at(doc, root, &[b"AcroForm"]) else { return Ok(()) };
    let want = match base {
        Some(b) => {
            let before = b.root().and_then(|r| dict_at(b, r, &[b"AcroForm"]));
            let fields = form.get(b"Fields").map(|f| doc.resolve(f)).and_then(|f| f.as_array().map(Vec::len)).unwrap_or(0);
            if before.is_none() && fields == 0 && form.iter().all(|(k, _)| matches!(k.as_slice(), b"Fields" | b"SigFlags")) {
                doc.update_dict(root, |c| {
                    c.remove(b"AcroForm");
                })?;
                return Ok(());
            }
            before.and_then(|f| f.int(b"SigFlags"))
        }
        None => {
            let current = form.int(b"SigFlags").unwrap_or(0);
            let flags = (current & !3) | i64::from(!sig_fields(doc).is_empty()) | if signatures_left { 2 } else { 0 };
            (flags != 0).then_some(flags)
        }
    };
    if form.int(b"SigFlags") != want {
        edit_at(doc, root, &[b"AcroForm"], |form| match want {
            Some(flags) => form.set(b"SigFlags".to_vec(), Object::Int(flags)),
            None => {
                form.remove(b"SigFlags");
            }
        })?;
    }
    Ok(())
}

/// The same object, however its strings are written: an encrypted file's update writes them in
/// hex where the original may have them literal.
fn same(a: &Object, b: &Object) -> bool {
    let same_dict = |x: &Dict, y: &Dict| x.len() == y.len() && x.iter().zip(y.iter()).all(|((kx, vx), (ky, vy))| kx == ky && same(vx, vy));
    match (a, b) {
        (Object::String(x), Object::String(y)) => x.bytes == y.bytes,
        (Object::Array(x), Object::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y)),
        (Object::Dict(x), Object::Dict(y)) => same_dict(x, y),
        (Object::Stream(x), Object::Stream(y)) => same_dict(&x.dict, &y.dict) && x.raw == y.raw,
        _ => a == b,
    }
}

/// Signing stamps the modification date, adding an information dictionary for it when the file
/// had none: put back what `base` had when that date is all that changed. A save of what else
/// changed since stamps the date again.
fn restore_info(out: &mut Document, base: &Document) {
    let without_date = |d: &Dict| {
        let mut d = d.clone();
        d.remove(b"ModDate");
        d
    };
    let Some(ir) = out.trailer().reference(b"Info") else { return };
    let Some(now) = out.get(ir).as_dict().cloned() else { return };
    match base.trailer().reference(b"Info") {
        Some(before_ref) if before_ref == ir => {
            if let Some(before) = base.get(ir).as_dict().cloned()
                && without_date(&before) == without_date(&now)
            {
                out.set(ir, Object::Dict(before));
            }
        }
        None if without_date(&now).is_empty() => {
            out.trailer_mut().remove(b"Info");
            out.free(ir);
        }
        _ => {}
    }
}
