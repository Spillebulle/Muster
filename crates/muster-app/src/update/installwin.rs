//! The installer's window, and the worker under it.
//!
//! [`super::installer`] is the model — what the command line means, what
//! `msiexec` is asked, which step the bar is on — and this is the part that
//! opens a window and touches the operating system. That division is what makes
//! any of this checkable: nobody can cut a release to run the real thing
//! against, so everything that can be decided without one is decided over
//! there, where a test can reach it.
//!
//! The window is `eframe`'s, like the application's, rather than the bespoke
//! shell Umber built for the same job. Umber needs one because its installer
//! runs before wgpu exists and its splash has to paint without a GPU; Muster
//! has no such moment, and a second windowing stack to draw four labels and a
//! bar would be scaffolding with nothing under it.
//!
//! It is small and it says one thing, but it is still held to the design
//! language: the palette's tokens, a hairline, one primary button, and a bar
//! that draws an **empty track** while `msiexec` runs rather than animating
//! over a number nobody has.

use super::installer::{Command, Job, Step, installed_path, stage_helper};
use crate::theme::{Mode, Palette, metrics, text};
use egui::{Align, Layout, RichText, Sense, Stroke, vec2};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::Duration;

/// The window, in logical points. Small: it says one thing.
const WINDOW: [f32; 2] = [440.0, 250.0];

/// How often the window looks for news from the worker.
///
/// Eight frames a second, which is enough for a label to change and few enough
/// that a window sitting through a two-minute install costs nothing worth
/// measuring. The bar it drives does not animate; see `Step::progress`.
const TICK: Duration = Duration::from_millis(125);

/// Start the helper for a package, from a copy of this executable that the
/// installer will not be replacing.
///
/// Called by [`super::apply`] on the MSI path, immediately before Muster exits.
/// Muster's own process id goes with it so the helper knows what to wait for.
pub fn spawn(package: &Path, version: &str) -> Result<(), String> {
    let dir = package.parent().unwrap_or_else(|| Path::new("."));
    let helper = stage_helper(dir)?;
    std::process::Command::new(&helper)
        .arg(super::installer::FLAG)
        .arg(package)
        .arg(std::process::id().to_string())
        .arg(version)
        // Where to start Muster from afterwards. This helper is a copy in the
        // temporary directory, so its own `current_exe` is the updater.
        .arg(std::env::current_exe().unwrap_or_default())
        .spawn()
        .map_err(|e| {
            format!(
                "Muster could not start the updater at {}: {e}",
                helper.display()
            )
        })?;
    Ok(())
}

/// Be the installer. Returns once the window has closed.
///
/// An update starts working immediately: it was asked for, and somebody is
/// watching a countdown in the Muster that spawned this. Setup waits, because
/// it was double-clicked by somebody who has not agreed to anything yet, so the
/// window opens on [`Step::Ready`] with an Install button.
pub fn show(mut job: Job) -> Result<(), Box<dyn std::error::Error>> {
    // Setup carries its package on its own end. Lifting it out here rather than
    // on the worker means a file that is not an installer says so at once,
    // instead of after a button has been pressed.
    let mut failure = None;
    if job.setup {
        match unpack_payload() {
            Ok((package, version)) => {
                job.package = package;
                if job.version.is_empty() {
                    job.version = version;
                }
            }
            Err(why) => failure = Some(why),
        }
    }

    let start = job.setup && failure.is_none();
    let title = if job.setup {
        // Setup is not an update, and saying so matters: somebody installing
        // Muster for the first time has never had a version to update, and the
        // title is what the task bar and Alt-Tab show.
        "Install Muster".to_string()
    } else {
        "Muster update".to_string()
    };

    let step = match failure {
        Some(why) => Step::Failed(why),
        None if start => Step::Ready,
        None => Step::WaitingForMuster,
    };

    let mut window = Installer {
        job,
        step,
        news: None,
        worker: None,
        log: None,
        mode: Mode::Dark,
        started: start,
    };
    // An update was already agreed to, so it gets on with it. Setup waits for
    // the button.
    if !window.started && !matches!(window.step, Step::Failed(_)) {
        window.begin();
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(WINDOW)
            .with_resizable(false)
            .with_title(title)
            .with_icon(crate::art::window_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "io.github.spillebulle.muster.setup",
        options,
        Box::new(|cc| {
            crate::app::install_fonts(&cc.egui_ctx);
            window.mode = match cc.egui_ctx.style().visuals.dark_mode {
                true => Mode::Dark,
                false => Mode::Light,
            };
            crate::app::apply(&cc.egui_ctx, Palette::of(window.mode));
            Ok(Box::new(window))
        }),
    )?;
    Ok(())
}

/// Lift the package off the end of this executable and write it down.
///
/// The version is taken from the package's own file name, which is what
/// `examples/make-setup.rs` puts there.
fn unpack_payload() -> Result<(PathBuf, String), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Muster could not read its own program file: {e}"))?;
    let bytes = std::fs::read(&exe)
        .map_err(|e| format!("Muster could not read its own program file: {e}"))?;
    let package = super::payload::read(&bytes).ok_or_else(|| {
        "This copy of Muster's installer carries no package. Take a fresh one \
         from the releases page."
            .to_string()
    })?;

    let dir = std::env::temp_dir();
    let name = exe
        .file_stem()
        .map(|s| format!("{}.msi", s.to_string_lossy()))
        .unwrap_or_else(|| "muster-setup.msi".to_string());
    let to = dir.join(name);
    std::fs::write(&to, package).map_err(|e| {
        format!(
            "Muster could not write the package to {}: {e}",
            to.display()
        )
    })?;

    // `muster-setup-0.0.1-x64` becomes `0.0.1`, and nothing if it is not shaped
    // like that. Only ever displayed, so a miss costs a heading and not an
    // installation.
    let version = exe
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .and_then(|stem| {
            stem.split('-')
                .find(|part| {
                    part.split('.').count() == 3
                        && part.chars().all(|c| c.is_ascii_digit() || c == '.')
                })
                .map(|v| v.to_string())
        })
        .unwrap_or_default();
    Ok((to, version))
}

struct Installer {
    job: Job,
    step: Step,
    /// News from the worker, once there is a worker. `None` before setup has
    /// been told to start, and for a window that opened only to report why
    /// there is nothing to install.
    news: Option<Receiver<Step>>,
    /// Held so the thread is joined rather than detached when the window goes.
    worker: Option<std::thread::JoinHandle<()>>,
    /// The installer's log, once there is one worth naming. Held so the failure
    /// screen can offer it.
    log: Option<PathBuf>,
    mode: Mode,
    /// Whether the work has been asked for. Setup's Install button sets it.
    started: bool,
}

impl Installer {
    /// Start the work. Called once, either straight away for an update or from
    /// the Install button for setup.
    fn begin(&mut self) {
        let (tx, rx) = channel();
        self.news = Some(rx);
        let package = self.job.package.clone();
        let parent = self.job.parent;
        let target = self.job.target.clone();
        let setup = self.job.setup;
        // The work runs on a thread and the window draws: the alternative is a
        // window that stops answering for as long as `msiexec` takes, which on
        // a slow machine is the whole install.
        self.worker = Some(std::thread::spawn(move || {
            // Setup has no Muster to wait for: it *is* the first one. An update
            // does, and it is the step that could hang, so it is named rather
            // than folded into the next.
            if !setup && let Some(pid) = parent {
                let _ = tx.send(Step::WaitingForMuster);
                wait_for(pid);
            }
            let _ = tx.send(Step::AskingPermission);
            let command = Command::for_package(&package);
            // The prompt is up until `install` reports the installer has
            // started, which is the moment consent was given. Two steps rather
            // than one because they fail differently and look different: a
            // prompt waiting on somebody, and Windows working.
            let running = tx.clone();
            match install(&command, &move || {
                let _ = running.send(Step::Installing);
            }) {
                Ok(()) => {
                    let _ = tx.send(Step::Starting);
                    // Where to start it from differs between the two. An update
                    // knows the path already: it is the Muster that spawned
                    // this helper, carried in `Job::target`. A first install has
                    // no such Muster to have asked, so the path is the one the
                    // package itself uses.
                    let exe = match target.clone() {
                        Some(path) => Some(path),
                        None if setup => {
                            installed_path(std::env::var("ProgramFiles").ok().as_deref())
                        }
                        None => None,
                    };
                    let started = exe
                        .ok_or_else(|| "Muster does not know where it was installed".to_string())
                        .and_then(|exe| {
                            std::process::Command::new(&exe)
                                .spawn()
                                .map(|_| ())
                                .map_err(|e| format!("{e}"))
                        });
                    match started {
                        Ok(()) => {
                            let _ = tx.send(Step::Finished);
                        }
                        // **The package went in.** Only the relaunch did not,
                        // and that is a nicety rather than the job: reporting it
                        // as a failed installation would send somebody looking
                        // for a problem that is not there.
                        Err(why) => {
                            log::warn!("installed, but could not start Muster: {why}");
                            let _ = tx.send(Step::Installed);
                        }
                    }
                }
                Err(why) => {
                    let _ = tx.send(Step::Failed(why));
                }
            }
        }));
    }

    /// Take whatever the worker has said since the last frame.
    fn poll(&mut self) {
        let Some(news) = self.news.as_ref() else {
            return;
        };
        loop {
            match news.try_recv() {
                Ok(step) => {
                    if matches!(step, Step::Failed(_)) {
                        self.log = Some(Command::for_package(&self.job.package).log);
                    }
                    self.step = step;
                }
                // The worker has finished and dropped its end. Whatever it last
                // said is the final answer.
                Err(TryRecvError::Disconnected) => {
                    self.news = None;
                    return;
                }
                Err(TryRecvError::Empty) => return,
            }
        }
    }
}

impl eframe::App for Installer {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.step.holds_work() {
            ctx.request_repaint_after(TICK);
        }
        // Nothing left to say and nothing running: the window has done its job.
        if matches!(self.step, Step::Finished) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        let p = Palette::of(self.mode);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(p.window)
                    .inner_margin(egui::Margin::same(metrics::S4 as i8)),
            )
            .show(ctx, |ui| {
                let heading = if self.job.setup {
                    match self.job.version.is_empty() {
                        true => "Install Muster".to_string(),
                        false => format!("Install Muster {}", self.job.version),
                    }
                } else {
                    match self.job.version.is_empty() {
                        true => "Updating Muster".to_string(),
                        false => format!("Updating Muster to {}", self.job.version),
                    }
                };
                ui.label(
                    RichText::new(heading)
                        .size(text::HEADING)
                        .color(p.text_strong),
                );
                ui.add_space(metrics::S3);

                progress(ui, p, self.step.progress());
                ui.add_space(metrics::S2);

                ui.label(
                    RichText::new(self.step.label())
                        .size(text::BODY)
                        .color(p.text),
                );

                // The one place the failure screen earns its keep: it names the
                // log rather than leaving somebody with no idea why.
                if let (Step::Failed(_), Some(log)) = (&self.step, &self.log) {
                    ui.add_space(metrics::S1);
                    ui.label(
                        RichText::new(format!("The installer's log is at {}", log.display()))
                            .size(text::TINY)
                            .color(p.text_dim),
                    );
                }

                ui.with_layout(Layout::bottom_up(Align::RIGHT), |ui| {
                    ui.horizontal(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            // At most one primary per view, §7.6, and it is
                            // whichever action the window exists for.
                            match &self.step {
                                Step::Ready => {
                                    if button(ui, p, "Install", true).clicked() {
                                        self.started = true;
                                        self.begin();
                                    }
                                    if button(ui, p, "Cancel", false).clicked() {
                                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                }
                                Step::Installed | Step::Failed(_) => {
                                    let close = button(ui, p, "Close", true);
                                    if close.clicked() {
                                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                }
                                // Working. Nothing to press, and no Cancel that
                                // would lie: `msiexec` cannot be called back
                                // once Windows has it.
                                _ => {}
                            }
                        });
                    });
                });
            });
    }
}

/// A bar that draws empty when it does not know.
///
/// `CLAUDE.md` refuses an animated bar over an unknown everywhere, and this is
/// the case it was written for: `msiexec` reports nothing at all, so `None`
/// paints the track and nothing in it.
fn progress(ui: &mut egui::Ui, p: Palette, fraction: Option<f32>) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 4.0), Sense::hover());
    ui.painter().rect_filled(rect, 2.0, p.control);
    if let Some(f) = fraction {
        let filled = egui::Rect::from_min_size(
            rect.left_top(),
            vec2(rect.width() * f.clamp(0.0, 1.0), rect.height()),
        );
        ui.painter().rect_filled(filled, 2.0, p.accent);
    }
}

/// A button, drawn rather than egui's, and `primary` is the accent-filled one.
fn button(ui: &mut egui::Ui, p: Palette, label: &str, primary: bool) -> egui::Response {
    let ink = if primary { p.accent_ink } else { p.text };
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        egui::FontId::proportional(text::CONTROL),
        ink,
    );
    let size = vec2(galley.size().x + metrics::S4 * 2.0, metrics::BUTTON);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    let fill = match (primary, response.hovered()) {
        (true, _) => p.accent,
        (false, true) => p.control_hover,
        (false, false) => p.control,
    };
    ui.painter().rect_filled(rect, metrics::RADIUS, fill);
    if !primary {
        ui.painter().rect_stroke(
            rect,
            metrics::RADIUS,
            Stroke::new(metrics::HAIRLINE, p.line),
            egui::StrokeKind::Inside,
        );
    }
    let at = egui::pos2(
        rect.center().x - galley.size().x / 2.0,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(at, galley, ink);
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------
// The platform
// ---------------------------------------------------------------------------

/// Wait for a process to end, giving up after a while.
///
/// The timeout is what stops the helper hanging for ever behind a Muster that
/// will not close. Going ahead anyway is the better failure: Windows Installer
/// will refuse to replace a file in use and say so, which the window then
/// reports, where waiting for ever leaves a window that never changes.
#[cfg(windows)]
fn wait_for(pid: u32) {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    const GIVE_UP_MS: u32 = 120_000;
    // SAFETY: `OpenProcess` takes a plain id and returns null on failure, which
    // is the case where the process has already gone — exactly what is being
    // waited for.
    unsafe {
        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return;
        }
        let waited = WaitForSingleObject(handle, GIVE_UP_MS);
        if waited != WAIT_OBJECT_0 {
            log::warn!("gave up waiting for Muster (pid {pid}) to close");
        }
        CloseHandle(handle);
    }
}

#[cfg(not(windows))]
fn wait_for(_pid: u32) {}

/// Run the installer, elevated, and wait for it.
///
/// `ShellExecuteExW` with the `runas` verb rather than `Command::spawn`, and
/// that is the whole of why this is not four lines: an MSI installing for the
/// whole machine needs administrator rights, and a plain spawn from an
/// unelevated Muster would have `msiexec` fail with "you must be an
/// administrator" — silently, because `/qn` has no interface to say it in.
/// `runas` is what raises the one consent prompt this install shows.
#[cfg(windows)]
fn install(command: &Command, started: &dyn Fn()) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let verb = wide("runas");
    let file = wide(&command.program.to_string_lossy());
    let parameters = wide(&command.parameters());

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    // `NOCLOSEPROCESS` is what hands back a handle to wait on; without it there
    // is no way to know whether the install worked, and the window would say
    // "done" the instant the prompt was answered.
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_HIDE;

    // SAFETY: every pointer above outlives the call, and `info` is zeroed
    // before its fields are set so the ones not used are null.
    let launched = unsafe { ShellExecuteExW(&mut info) };
    if launched == 0 {
        // By far the most likely reason, and worth naming rather than reporting
        // a Windows error number: the consent prompt was declined.
        return Err(
            "Windows did not allow the installation to start. It may have been \
             declined at the permission prompt."
                .to_string(),
        );
    }
    if info.hProcess.is_null() {
        return Err("Windows did not report the installer's progress.".to_string());
    }

    // The consent prompt has been answered and Windows Installer is running.
    started();

    // SAFETY: `hProcess` is non-null and owned by this function until closed.
    let code = unsafe {
        let waited = WaitForSingleObject(info.hProcess, u32::MAX);
        let mut code: u32 = 0;
        let read = GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        if waited != WAIT_OBJECT_0 || read == 0 {
            return Err("Muster could not tell whether the installation finished.".to_string());
        }
        code
    };

    match code {
        0 => Ok(()),
        // 3010 is "a restart is required to finish", which `/norestart` asks
        // for rather than performing. The files are in place.
        3010 => Ok(()),
        1602 => Err("The installation was cancelled.".to_string()),
        other => Err(format!(
            "Windows Installer stopped with error {other}. Muster is still the \
             version you had."
        )),
    }
}

#[cfg(not(windows))]
fn install(_command: &Command, _started: &dyn Fn()) -> Result<(), String> {
    Err("Muster only installs a package this way on Windows.".to_string())
}
