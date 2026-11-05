//! Signatures panel ▸ Clear Signature: only its signer can, with the digital ID that made it and
//! its password (`pdfcraft_sign::clear_signature`). Clearing saves, as signing does.

#[cfg(not(target_arch = "wasm32"))]
use crate::file_filter::AddFilterAnyCase as _;
use std::path::PathBuf;

use super::dialog::{error, id_rows, title};
use super::{Align, DigitalIdEntry, Layout, PdfCraftApp, Tokens, open_id, widgets};

/// The Clear Signature dialog's state.
#[derive(Clone, Debug, PartialEq)]
pub struct ClearDraft {
    /// The signed field.
    pub field: String,
    /// Who signed it, as the panel names them; empty when the signature doesn't say.
    pub signer: String,
    pub selected: Option<usize>,
    pub password: String,
    pub error: Option<String>,
}

/// `message` as a sentence: an engine refusal is a clause ("this digital ID did not make…").
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    let Some(first) = chars.next() else { return String::new() };
    let mut out: String = first.to_uppercase().chain(chars).collect();
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

impl PdfCraftApp {
    /// Signatures panel ▸ Clear Signature…: ask for the digital ID the signature was made with,
    /// choosing first the one named like the signer.
    pub fn start_clearing(&mut self, field: String, signer: String) {
        self.refresh_os_key_store_ids();
        let usable = |e: &DigitalIdEntry| e.unusable.is_none();
        let ids = &self.digital_ids;
        let selected = ids.iter().position(|e| usable(e) && !signer.is_empty() && e.name == signer).or_else(|| ids.iter().position(usable));
        self.clear_draft = Some(ClearDraft { field, signer, selected, password: String::new(), error: None });
        self.dialog = Some(crate::Dialog::ClearSignature);
    }

    /// Clear the signature with the chosen ID, then choose where to save. The ID is checked
    /// first, so a wrong password or another person's ID is said in the dialog. Once the picker
    /// shows, the dialog closes and an error from there on arrives as a notice; if no picker
    /// could show, the dialog stays open.
    fn finish_clearing(&mut self) -> Result<(), String> {
        // What's typed in a form field is kept in the cleared file, as it is signed (#166).
        if !self.commit_form_typing() {
            return Err(String::new());
        }
        let Some((_, doc_id)) = self.active_ids() else { return Err("no document".into()) };
        let d = self.clear_draft.clone().ok_or("nothing to clear")?;
        let entry = d.selected.and_then(|i| self.digital_ids.get(i)).filter(|e| e.unusable.is_none()).cloned().ok_or("Choose a digital ID.")?;
        let id = open_id(&entry, &d.password)?;
        let cleared = self.session.clear_signature(doc_id, &d.field, &id).map_err(|e| sentence(&e.to_string()))?;
        let doc = self.session.get(doc_id);
        let name = doc.map(|d| d.name.clone()).unwrap_or_default();
        #[cfg(not(target_arch = "wasm32"))]
        let folder = doc.and_then(|d| d.path.clone());
        let save = move |app: &mut Self, path: PathBuf| -> Result<(), String> {
            crate::editing::write_atomically(&path.to_string_lossy(), cleared.bytes.as_slice()).map_err(|e| format!("Could not save: {e}"))?;
            // Our own write is not a change on disk to reload (#431).
            #[cfg(not(target_arch = "wasm32"))]
            app.watch.known_now(doc_id, &path.to_string_lossy());
            // As after signing, the edit history goes: its states hold the signature.
            app.session.mark_signed(doc_id, cleared.bytes.clone(), Some(path.to_string_lossy().into_owned())).map_err(|e| e.to_string())?;
            #[cfg(target_os = "macos")]
            crate::macos_association::repair(&path);
            if let Some(view) = app.views.iter_mut().find(|v| v.id == doc_id) {
                view.invalidate_content();
            }
            app.notify_fmt("Signature cleared and saved to {path}", &[("path", &path.display().to_string())]);
            Ok(())
        };
        match self.save_override.clone() {
            Some(p) => save(self, PathBuf::from(p)),
            #[cfg(not(target_arch = "wasm32"))]
            None => {
                // Offered under the document's own name: clearing is a change to this document.
                let dialog = rfd::AsyncFileDialog::new().add_filter_any_case("PDF", &["pdf"]).set_file_name(name);
                let dialog = crate::editing::in_document_folder(dialog, folder.as_deref());
                // The cleared file is the document as it is now: the pick is dropped (with a
                // notice) if it is edited or switched away from meanwhile.
                let asked = self.ask_one(crate::pickers::Ask::Save(dialog), Some(doc_id), move |app, path| {
                    if let Err(e) = save(app, path)
                        && !e.is_empty()
                    {
                        app.notify(e);
                    }
                });
                if asked { Ok(()) } else { Err(String::new()) }
            }
            #[cfg(target_arch = "wasm32")]
            None => {
                let _ = (name, save);
                Err(String::new())
            }
        }
    }
}

/// Draw Clear Signature; returns `true` when the dialog should close.
pub(crate) fn clear_dialog(ui: &mut egui::Ui, app: &mut PdfCraftApp, t: &Tokens) -> bool {
    title(ui, "Clear Signature");
    let ids = app.digital_ids.clone();
    let Some(d) = app.clear_draft.as_mut() else { return true };
    let ask = if d.signer.is_empty() {
        tl!("Only the person who signed can clear this signature. Choose the digital ID it was signed with and enter its password.").to_string()
    } else {
        crate::i18n::fmt(
            tl!("Only the person who signed can clear this signature. Choose the digital ID that {name} signed with and enter its password."),
            &[("name", &d.signer)],
        )
    };
    ui.add(egui::Label::new(ask).wrap());
    ui.add_space(6.0);
    egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
        let (clicked, _) = id_rows(ui, &ids, &mut d.selected, t);
        if clicked {
            d.error = None;
        }
    });
    ui.add_space(8.0);
    let (mut go, mut close) = (false, false);
    match d.selected.and_then(|i| ids.get(i)) {
        Some(e) if e.path.starts_with("keychain:") || e.path.starts_with("windows:") => {
            ui.label(
                egui::RichText::new(if e.path.starts_with("windows:") {
                    tl!("The key is in the Windows certificate store, which may ask to allow PdfCraft to use it.")
                } else {
                    tl!("The key is in the macOS Keychain, which may ask to allow PdfCraft to use it.")
                })
                .small()
                .color(t.text_muted),
            );
        }
        Some(_) => {
            ui.horizontal(|ui| {
                let l = ui.label(tl!("Digital ID password"));
                let r = ui.add(crate::widgets::line(&mut d.password).password(true).desired_width(200.0)).labelled_by(l.id);
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
            });
        }
        None => {}
    }
    ui.add_space(6.0);
    ui.add(
        egui::Label::new(
            egui::RichText::new(tl!("The file goes back to how it was before this signature, with later changes kept. This can't be undone."))
                .small()
                .color(t.text_muted),
        )
        .wrap(),
    );
    ui.add_space(6.0);
    error(ui, &d.error);
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.add_enabled_ui(d.selected.is_some(), |ui| widgets::pill_button(ui, tl!("Clear"), true)).inner.clicked() {
                go = true;
            }
            if widgets::pill_button(ui, tl!("Cancel"), false).clicked() {
                close = true;
            }
        });
    });
    if go {
        match app.finish_clearing() {
            Ok(()) => {
                app.clear_draft = None;
                return true;
            }
            Err(e) => {
                if let Some(d) = app.clear_draft.as_mut() {
                    d.error = Some(e);
                }
            }
        }
    }
    close
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_engine_refusal_reads_as_a_sentence() {
        assert_eq!(super::sentence("only its signer can clear it"), "Only its signer can clear it.");
        assert_eq!(super::sentence("The password is incorrect."), "The password is incorrect.");
        assert_eq!(super::sentence(""), "");
    }
}
