//! Finding the node that lights the panel, and the top of the range the
//! slider spans within it. The pages keep their light in a sysfs file;
//! which file that is, and whether its own maximum is what the panel shows
//! at full slider, has been assumed so far of Qualcomm's display driver.
//! Other makers' differ: MediaTEK builds the panel's light as an LED class
//! device and may compile the backlight class out altogether, and its
//! driver offers no high-brightness tier to trim the range against.

use anyhow::{anyhow, ensure, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// The first node the pages can light the panel with, under the `sys` root
/// of some system's /sys.
///
/// A node is a folder holding a `brightness` file to write and a
/// `max_brightness` file to scale against, whether the kernel found it as a
/// backlight or as an LED: the two classes name those files the same and
/// mean the same by them, so everything past this point treats them alike.
/// What the classes differ in is where the panel's light lives, and a phone
/// built on Qualcomm's display driver says nothing of MediaTEK's placing
/// and the other way about; so each kind is tried, and only when one holds
/// nothing is the next asked.
pub fn node(sys: &Path) -> Result<PathBuf> {
    // A kernel built without the class leaves no folder to read at all,
    // which asks for the next kind rather than failing: on the RedMi Note
    // 9 5G /sys/class/backlight is there but empty, and on phones whose
    // kernel compiles neither the folder nor its contents is absent. Other
    // errors say so; a class that is there yet unreadable is not a missing
    // one, and hiding that behind a fallthrough would leave a puzzling
    // brightness at worst and a silent dark screen at best.
    let listed = |class: &str| -> Result<Vec<PathBuf>> {
        let path = sys.join("class").join(class);
        match fs::read_dir(&path) {
            Ok(entries) => {
                let mut dirs: Vec<PathBuf> = entries.map(|e| e.map(|e| e.path())).collect::<std::io::Result<_>>()?;
                dirs.sort();
                Ok(dirs)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    };
    let backlight = listed("backlight")?;
    if let Some(dir) = backlight
        .iter()
        // Qualcomm panels expose panel0-backlight; take it when present.
        .find(|d| d.file_name().is_some_and(|n| n == "panel0-backlight"))
        .or(backlight.first())
    {
        return Ok(dir.clone());
    }
    // Without a backlight class, a MediaTEK phone's display driver has left
    // the panel's light as the LED lcd-backlight, whose brightness takes
    // the same plain levels. A name saying backlight is asked next, for
    // drivers that name it after their panel rather than the LCD; the
    // other LEDs — the vibrator, the camera's flash and torch — take their
    // own names and light nothing, so they are passed over.
    let leds = listed("leds")?;
    leds.iter()
        .find(|d| d.file_name().is_some_and(|n| n == "lcd-backlight"))
        .or_else(|| leds.iter().find(|d| d.file_name().is_some_and(|n| n.to_string_lossy().contains("backlight"))))
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "no backlight device: {} holds none and {} nothing named after one",
                sys.join("class/backlight").display(),
                sys.join("class/leds").display()
            )
        })
}

/// How a panel's node in the device tree may give its normal maximum: the
/// property holding it, and the one holding the whole range on the same
/// scale. The 13 Ultra's panel gives both on a finer scale of its own that
/// spans the same light as the backlight's range; the 17 Ultra's gives them
/// on the backlight's own scale. The panels of the Xiaomi 13 and 15, of the
/// 14 and the K80 series and one of the K90's give it only as the level
/// their factory tests drive the panel to, on the backlight's own scale:
/// the 13 Ultra's panels give that level as well, and it comes to the same
/// half of their range as the normal maximum they give.
const NORMAL_MAX: [(&str, &str); 3] = [
    ("mi,normal-max-brightness-clone", "mi,max-brightness-clone"),
    ("mi,max-brightness-normal", "qcom,mdss-dsi-bl-max-level"),
    ("mi,mdss-dsi-fac-bl-max-level", "qcom,mdss-dsi-bl-max-level"),
];

/// The raw level to give the slider's full: the panel's normal maximum out
/// of its node's `max`, as [`normal_max`] works it out where the display
/// driver is Qualcomm's.
///
/// Other drivers lay no high-brightness tier above the normal range for the
/// stock slider to stop short of, so their node's maximum already is the
/// full slider: asking the panel of the device tree then would either fail
/// outright, as on MediaTEK where there is no msm_drm to ask, or read out
/// of a tree the driver never wrote. Only the absent parameter falls back
/// this way. Where the parameter is there and yet the panel's normal
/// maximum cannot be read, that is taken as what it is most likely — a
/// misreading of a Qualcomm panel's tiers — and it fails saying so, because
/// a quiet fallthrough would let the slider reach light only the factory
/// test drives the panel to, holding it there past its rated maximum.
pub fn top(sys: &Path, proc: &Path, max: u32) -> Result<u32> {
    let param = sys.join("module/msm_drm/parameters/dsi_display0");
    if !param.exists() {
        eprintln!("no msm_drm: the slider spans the node's whole range of {max}");
        return Ok(max);
    }
    normal_max(&param, proc, max)
}

/// The raw backlight level, out of `max`, at the panel's normal maximum.
/// Above it the panel runs in high brightness mode, which the stock system
/// keeps for strong sunlight and its slider does not reach. The panel the
/// display driver booted with gives that maximum in the device tree.
fn normal_max(param: &Path, proc: &Path, max: u32) -> Result<u32> {
    let boot = fs::read_to_string(param).with_context(|| format!("read {}", param.display()))?;
    // The panel's node, then its configuration after a colon, as in
    // "qcom,mdss_dsi_m1_42_02_0a_dsc_cmd:"; the driver takes no name
    // without the colon either.
    let (name, _) = boot.trim().split_once(':').with_context(|| format!("{} names no panel: {boot:?}", param.display()))?;
    let soc = proc.join("device-tree/soc");
    let node = fs::read_dir(&soc)
        .with_context(|| format!("read {}", soc.display()))?
        .map(|e| e.map(|e| e.path().join(name)))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .find(|p| p.is_dir())
        .ok_or_else(|| anyhow!("panel {name} is not in the device tree"))?;
    let cell = |prop: &str| -> Result<u32> {
        let path = node.join(prop);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let cell: [u8; 4] = bytes.as_slice().try_into().map_err(|_| anyhow!("{} is not one cell", path.display()))?;
        Ok(u32::from_be_bytes(cell))
    };
    let (normal, full) = NORMAL_MAX
        .iter()
        .find(|(normal, _)| node.join(normal).exists())
        .with_context(|| format!("panel {name} gives its normal maximum as none of {NORMAL_MAX:?}"))?;
    let (normal, full) = (cell(normal)?, cell(full)?);
    ensure!(normal > 0 && normal <= full, "panel {name}: normal maximum {normal} out of {full}");
    Ok((f64::from(max) * f64::from(normal) / f64::from(full)).round() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The roots of a fake /sys and /proc for one test, in the temporary
    /// folder. On the phone the kernel makes these trees; here the test
    /// lays the nodes its phone would have made, and the functions read
    /// them as they read the kernel's.
    fn roots(test: &str) -> (PathBuf, PathBuf) {
        let at = std::env::temp_dir().join(format!("skyward-backlight-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&at);
        let sys = at.join("sys");
        let proc = at.join("proc");
        fs::create_dir_all(&sys).unwrap();
        fs::create_dir_all(&proc).unwrap();
        (sys, proc)
    }

    /// A node of a class, made as the kernel leaves them: a folder whose
    /// name is the device's, under /sys/class.
    fn device(sys: &Path, class: &str, name: &str) -> PathBuf {
        let dir = sys.join("class").join(class).join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_qualcomm_panel_gives_its_backlight_before_any_led() {
        let (sys, _) = roots("panel0");
        // keyboard-backlight sorts before it, as it does on phones that
        // have both, and an lcd-backlight LED sits unused beside them.
        let keyboard = device(&sys, "backlight", "keyboard-backlight");
        let panel0 = device(&sys, "backlight", "panel0-backlight");
        device(&sys, "leds", "lcd-backlight");
        assert_eq!(node(&sys).unwrap(), panel0, "panel0-backlight is taken wherever it is");
        assert!(keyboard.exists(), "and it is taken over the first of the class");
    }

    #[test]
    fn the_first_backlight_of_the_class_is_taken_without_a_panel0() {
        let (sys, _) = roots("first");
        device(&sys, "leds", "lcd-backlight");
        let panel = device(&sys, "backlight", "panel-backlight");
        device(&sys, "backlight", "zted backlight");
        assert_eq!(node(&sys).unwrap(), panel, "as the pages always took them, sorted and the first");
    }

    #[test]
    fn an_empty_backlight_class_sends_the_search_to_the_leds() {
        let (sys, _) = roots("empty");
        // The RedMi Note 9 5G: the class is mounted and holds nothing, so
        // the panel's light is only the LCD LED the display driver made.
        fs::create_dir_all(sys.join("class/backlight")).unwrap();
        device(&sys, "leds", "torch-light0");
        device(&sys, "leds", "vibrator");
        let lcd = device(&sys, "leds", "lcd-backlight");
        assert_eq!(node(&sys).unwrap(), lcd, "the LED named for the LCD lights the panel");
    }

    #[test]
    fn a_backlight_class_the_kernel_left_out_falls_through_too() {
        let (sys, _) = roots("absent");
        // A kernel compiled without CONFIG_BACKLIGHT_CLASS_DEVICE leaves
        // no folder to read at all; that is the same absence of a node.
        device(&sys, "leds", "panel-backlight");
        assert_eq!(node(&sys).unwrap(), sys.join("class/leds/panel-backlight"), "the first LED named after a backlight");
    }

    #[test]
    fn the_leds_that_light_nothing_are_passed_over() {
        let (sys, _) = roots("named");
        // Sorted, vibrator comes first, and a phone with a flash or torch
        // LED may hold those ahead of the panel's; writing levels meant
        // for the panel to one of them lights no screen.
        device(&sys, "leds", "vibrator");
        device(&sys, "leds", "flash-light0");
        let lcd = device(&sys, "leds", "lcd-backlight");
        assert_eq!(node(&sys).unwrap(), lcd, "the LED whose name says backlight is the panel's");
    }

    #[test]
    fn no_node_at_all_says_where_it_looked() {
        let (sys, _) = roots("none");
        fs::create_dir_all(sys.join("class/backlight")).unwrap();
        device(&sys, "leds", "vibrator");
        let why = format!("{:#}", node(&sys).unwrap_err());
        let both = [sys.join("class").join("backlight"), sys.join("class").join("leds")];
        assert!(both.iter().all(|p| why.contains(&p.display().to_string())), "it names both classes it searched: {why}");
        assert!(!why.contains("vibrator"), "and no node it passed over: {why}");
    }

    #[test]
    fn a_phone_without_msm_drm_slides_over_the_whole_of_its_range() {
        let (sys, proc) = roots("mtk");
        device(&sys, "leds", "lcd-backlight");
        // MediaTEK's lcd-backlight reaches its brightest at its own
        // maximum, which the stock slider reaches too; 2047 as the Note
        // 9 5G's node says it.
        assert_eq!(top(&sys, &proc, 2047).unwrap(), 2047, "the node's maximum is the full slider");
    }

    #[test]
    fn a_panel_of_msm_drm_still_cuts_the_range_at_its_normal_maximum() {
        let (sys, proc) = roots("hbm");
        device(&sys, "backlight", "panel0-backlight");
        fs::create_dir_all(sys.join("module/msm_drm/parameters")).unwrap();
        fs::write(sys.join("module/msm_drm/parameters/dsi_display0"), "qcom,mdss_dsi_nt667a:\n").unwrap();
        // The panel's node sits under a bus, not under soc itself, as on
        // the phone: the driver's parameter names the panel and the walk
        // looks for it one below each child of /proc/device-tree/soc.
        let panel = proc.join("device-tree/soc/1ae0000.qcom,mdss/qcom,mdss_dsi_nt667a");
        fs::create_dir_all(&panel).unwrap();
        fs::write(panel.join("mi,mdss-dsi-fac-bl-max-level"), 1500u32.to_be_bytes()).unwrap();
        fs::write(panel.join("qcom,mdss-dsi-bl-max-level"), 2000u32.to_be_bytes()).unwrap();
        assert_eq!(top(&sys, &proc, 4000).unwrap(), 3000, "the slider stops at three quarters, as the panel says");
    }

    #[test]
    fn a_laid_msm_drm_that_answers_nothing_fails_rather_than_falling_back() {
        let (sys, proc) = roots("broken");
        device(&sys, "backlight", "panel0-backlight");
        fs::create_dir_all(sys.join("module/msm_drm/parameters")).unwrap();
        // The driver booted; its parameter is there but says nothing the
        // tree answers. Giving the whole range back now would run the
        // slider into the high-brightness tier the stock system keeps it
        // out of, on a panel that is Qualcomm's after all.
        fs::write(sys.join("module/msm_drm/parameters/dsi_display0"), "none\n").unwrap();
        let why = format!("{:#}", top(&sys, &proc, 4095).unwrap_err());
        assert!(why.contains("names no panel"), "it says what the panel's answer lacked: {why}");
    }
}
