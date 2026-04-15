use std::time::Duration;

pub fn format_duration_2dp(duration: Duration) -> String {
    let ms = duration.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:.2} s", ms / 1_000.0)
    } else {
        format!("{:.2} ms", ms)
    }
}
