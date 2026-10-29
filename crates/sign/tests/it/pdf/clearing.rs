//! Clearing a signature as its signer (Acrobat: Clear Signature).

use super::*;
use pdfcraft_sign::Cleared;

const DATE: Option<&str> = Some("D:20261029120000Z");

fn id(file: &str) -> DigitalId {
    pkcs12::open(&data(file), "test").unwrap()
}

fn clear(bytes: &[u8], field: &str, id: &DigitalId) -> Result<Cleared, SignError> {
    pdfcraft_sign::clear_signature(&open(bytes), field, id, DATE)
}

fn refused(r: Result<Cleared, SignError>, what: &str) {
    match r {
        Err(SignError::Pdf(m)) => assert!(m.contains(what), "{m}"),
        other => panic!("expected a refusal naming {what:?}, got {:?}", other.map(|c| c.bytes.len())),
    }
}

/// `raw` written as hex anywhere in `file`, as a signature's `/Contents` carries its certificates.
fn holds_hex(file: &[u8], raw: &[u8]) -> bool {
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    String::from_utf8_lossy(file).to_ascii_lowercase().contains(&hex)
}

/// Every signature field by name, and whether it is signed.
fn listed(bytes: &[u8]) -> Vec<(String, bool)> {
    signatures(&open(bytes), bytes, &TrustStore::default()).into_iter().map(|s| (s.field, s.signed)).collect()
}

fn catalog(doc: &Document) -> Dict {
    doc.get(doc.root().unwrap()).as_dict().cloned().unwrap()
}

/// The subtypes of the annotations on the fixture's page.
fn annotations(bytes: &[u8]) -> Vec<String> {
    let doc = open(bytes);
    let page = doc.get(ObjRef { num: 3, generation: 0 }).as_dict().cloned().unwrap();
    let annots = page.get(b"Annots").map(|a| doc.resolve(a)).and_then(|a| a.as_array().cloned()).unwrap_or_default();
    annots.iter().filter_map(|a| doc.resolve(a).as_dict().and_then(|d| d.name(b"Subtype")).map(|s| String::from_utf8_lossy(s).into_owned())).collect()
}

/// Clearing the only signature gives back the file as it was before signing, byte for byte,
/// with RSA and ECDSA keys: a field that was there stays, empty, and one that signing drew
/// (visible or not) goes.
#[test]
fn clearing_the_only_signature_gives_back_the_file_as_it_was() {
    for file in ["rsa-aes.p12", "ec-p256.p12", "ec-p384.p12"] {
        let id = id(file);
        for (field, options, removed) in [
            ("Approval", SignOptions { field: Some("Approval".into()), ..opts() }, false),
            ("Signature1", opts(), true),
            ("Signature1", SignOptions { rect: None, ..opts() }, true),
        ] {
            let signed = pdfcraft_sign::sign(&open(&fixture()), &id, &options).unwrap();
            let cleared = clear(&signed, field, &id).unwrap();
            assert!(cleared.restored, "{file} {field}");
            assert_eq!(cleared.field_removed, removed, "{file} {field}");
            assert!(*cleared.bytes == fixture(), "{file} {field}: the file as it was before signing");
        }
    }
}

/// Only the signer clears a signature: another person's digital ID is refused, and so is one
/// that carries the signer's certificate with a key of its own (a certificate is public).
#[test]
fn only_the_signer_can_clear_a_signature() {
    let signer = id("ec-p256.p12");
    let signed = pdfcraft_sign::sign(&open(&fixture()), &signer, &opts()).unwrap();
    refused(clear(&signed, "Signature1", &id("rsa-aes.p12")), "only its signer can clear it");
    let forged = DigitalId {
        key: pdfcraft_sign::PrivateKey::generate_p256().unwrap(),
        certificate: signer.certificate.clone(),
        chain: Vec::new(),
        friendly_name: None,
    };
    refused(clear(&signed, "Signature1", &forged), "only its signer can clear it");
    assert!(clear(&signed, "Signature1", &signer).is_ok());
}

/// The last signature goes with its revision, and what was changed after it stays: the file
/// is cut back to before it (so the earlier signature still covers its bytes), and nothing of
/// the cleared signature is left. A signature under a later one waits until that one is cleared.
#[test]
fn clearing_the_last_signature_keeps_later_changes_and_earlier_signatures() {
    let (first_id, second_id) = (id("ec-p256.p12"), id("rsa-aes.p12"));
    let first = pdfcraft_sign::sign(&open(&fixture()), &first_id, &SignOptions { field: Some("Approval".into()), ..opts() }).unwrap();
    let second = pdfcraft_sign::sign(&open(&first), &second_id, &opts()).unwrap();
    let commented = edit_after(&second, add_comment);
    assert!(holds_hex(&commented, &second_id.certificate.raw), "the check below can see a signature's certificate");

    refused(clear(&commented, "Approval", &first_id), "a later signature covers");
    let cleared = clear(&commented, "Signature1", &second_id).unwrap();
    assert!(!cleared.restored && cleared.field_removed);
    assert!(cleared.bytes.starts_with(&first), "cut back to the revision before the signature");
    assert!(!holds_hex(&cleared.bytes, &second_id.certificate.raw), "nothing of the cleared signature is left");
    assert_eq!(listed(&cleared.bytes), [("Approval".to_string(), true)]);
    assert_eq!(annotations(&cleared.bytes), ["Widget", "Text"], "the comment made after signing stays");
    let approval = signatures(&open(&cleared.bytes), &cleared.bytes, &TrustStore::default()).remove(0);
    assert_eq!(approval.status, Status::Unknown, "{:?}", approval.details);
    // The comment, and the modification date this update stamps, as a save does.
    assert_eq!(approval.modification, Modification::Allowed(vec![kind::COMMENTS, kind::METADATA]), "{:?}", approval.details);

    // Now the first one can go too; the field stays, empty, and so does the comment.
    let again = clear(&cleared.bytes, "Approval", &first_id).unwrap();
    assert!(!again.restored && !again.field_removed);
    assert!(again.bytes.starts_with(&fixture()));
    assert!(!holds_hex(&again.bytes, &first_id.certificate.raw));
    assert_eq!(listed(&again.bytes), [("Approval".to_string(), false)]);
    assert_eq!(annotations(&again.bytes), ["Widget", "Text"]);
    // No signature is left to need append-only saves.
    let doc = open(&again.bytes);
    let form = catalog(&doc).get(b"AcroForm").and_then(|f| doc.resolve(f).as_dict().cloned()).unwrap();
    assert_eq!(form.int(b"SigFlags"), None, "as before signing");
}

/// A certification goes with its signature: the catalog's `/Perms` names it no more.
#[test]
fn a_certification_goes_with_its_signature() {
    let id = id("ec-p256.p12");
    let certified = pdfcraft_sign::sign(&open(&fixture()), &id, &SignOptions { field: Some("Approval".into()), certify: Some(2), ..opts() }).unwrap();
    assert!(catalog(&open(&certified)).contains(b"Perms"));
    assert!(*clear(&certified, "Approval", &id).unwrap().bytes == fixture());
    let commented = edit_after(&certified, add_comment);
    let cleared = clear(&commented, "Approval", &id).unwrap();
    let doc = open(&cleared.bytes);
    assert!(!catalog(&doc).contains(b"Perms"));
    assert_eq!(listed(&cleared.bytes), [("Approval".to_string(), false)]);
    assert_eq!(annotations(&cleared.bytes), ["Widget", "Text"]);
}

/// A document timestamp has no signer, so it is never cleared, and the signature it covers waits.
#[test]
fn document_timestamps_are_not_cleared_and_hold_back_what_they_cover() {
    let tsa = TestTsa { id: tsa_id(), time: Time { year: 2026, month: 10, day: 6, hour: 12, minute: 0, second: 0 } };
    let id = id("ec-p256.p12");
    let signed = pdfcraft_sign::sign(&open(&fixture()), &id, &opts()).unwrap();
    let stamped = pdfcraft_sign::timestamp_document(&open(&signed), &tsa, "D:20261006130000Z").unwrap();
    refused(clear(&stamped, "Signature1", &id), "a later signature covers");
    // A timestamp written as a field's value (Documenso's `Timestamp_1`).
    let field = fixture_with(
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>",
        &[b"<< /FT /Sig /T (Timestamp_1) /V 8 0 R >>", b"<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 /ByteRange [0 1 2 3] /Contents <00> >>"],
    );
    refused(clear(&field, "Timestamp_1", &id), "document timestamp");
}

#[test]
fn unsigned_and_unknown_fields_are_refused() {
    let id = id("ec-p256.p12");
    refused(clear(&fixture(), "Approval", &id), "is not signed");
    refused(clear(&fixture(), "Nowhere", &id), "there is no signature field");
}

/// A signature in the file's first revision has nothing before it to cut back to: the file is
/// written again in full, the field stays, empty, and no signature is left to keep saves append-only.
#[test]
fn a_signature_in_the_first_revision_is_cleared_with_a_full_write() {
    let bytes = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >> endobj
trailer << /Root 1 0 R >>
%%EOF"
        .to_vec();
    let id = id("ec-p256.p12");
    let signed = pdfcraft_sign::sign(&open(&bytes), &id, &SignOptions { rect: None, ..opts() }).unwrap();
    assert_eq!(open(&signed).revisions().len(), 1);
    let cleared = clear(&signed, "Signature1", &id).unwrap();
    assert!(!cleared.restored && !cleared.field_removed);
    assert!(!holds_hex(&cleared.bytes, &id.certificate.raw));
    assert_eq!(listed(&cleared.bytes), [("Signature1".to_string(), false)]);
    let doc = open(&cleared.bytes);
    let form = catalog(&doc).get(b"AcroForm").and_then(|f| doc.resolve(f).as_dict().cloned()).unwrap();
    assert_eq!(form.int(b"SigFlags"), Some(1), "a signature field, no signatures");
}

/// The security store's `/VRI` entry for the signature goes with it; the evidence stays.
#[test]
fn the_signatures_entry_in_the_security_store_goes_with_it() {
    use pdfcraft_sign::dss::{self, Evidence};
    let id = id("ec-p256.p12");
    let signed = pdfcraft_sign::sign(&open(&fixture()), &id, &opts()).unwrap();
    let evidence = Evidence { certs: vec![id.certificate.raw.clone()], ocsps: Vec::new(), crls: Vec::new() };
    let ltv = dss::embed(&open(&signed), &evidence).unwrap();
    let store = |bytes: &[u8]| {
        let doc = open(bytes);
        catalog(&doc).get(b"DSS").and_then(|d| doc.resolve(d).as_dict().cloned()).unwrap()
    };
    assert!(store(&ltv).contains(b"VRI"));
    let cleared = clear(&ltv, "Signature1", &id).unwrap();
    assert!(!store(&cleared.bytes).contains(b"VRI"));
    assert!(store(&cleared.bytes).contains(b"Certs"));
}

/// A protected document is cleared as its permissions allow, as it is signed (Table 22), and
/// a cleared one is the protected file as it was.
#[test]
fn encrypted_documents_are_cleared_only_as_their_permissions_allow() {
    let id = id("ec-p256.p12");
    let base = protected(pdfcraft_cos::Algorithm::Aes256, FILL_AND_SIGN_ONLY);
    let signed = pdfcraft_sign::sign(&open_pw(&base, None), &id, &SignOptions { field: Some("Approval".into()), ..opts() }).unwrap();
    let cleared = pdfcraft_sign::clear_signature(&open_pw(&signed, None), "Approval", &id, DATE).unwrap();
    assert!(*cleared.bytes == base);
    // A field the owner drew is a change to the page the user may not make.
    let drawn = pdfcraft_sign::sign(&open_pw(&base, Some("owner")), &id, &opts()).unwrap();
    refused(pdfcraft_sign::clear_signature(&open_pw(&drawn, None), "Signature1", &id, DATE), "removing the signature field");
    assert!(pdfcraft_sign::clear_signature(&open_pw(&drawn, Some("owner")), "Signature1", &id, DATE).is_ok());
    // Print-only settings allow no form filling at all.
    let print_only = protected(pdfcraft_cos::Algorithm::Aes256, -3900);
    let signed = pdfcraft_sign::sign(&open_pw(&print_only, Some("owner")), &id, &SignOptions { field: Some("Approval".into()), ..opts() }).unwrap();
    refused(pdfcraft_sign::clear_signature(&open_pw(&signed, None), "Approval", &id, DATE), "filling in form fields");
}
