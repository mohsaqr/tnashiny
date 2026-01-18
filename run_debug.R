# Debug runner for TNA app
# Logs all output to file and console

log_file <- "/tmp/tna_shiny_debug.log"
cat("", file = log_file)  # Clear log file

# Custom message handler to log to file
log_message <- function(...) {
  msg <- paste0(format(Sys.time(), "[%H:%M:%S] "), paste(..., collapse = ""), "\n")
  cat(msg)
  cat(msg, file = log_file, append = TRUE)
}

log_message("=== TNA App Debug Session ===")

# Load environment
readRenviron(".Renviron")
log_message("Client Secret loaded: ", nchar(Sys.getenv("GOOGLE_CLIENT_SECRET")), " chars")

# Set options
options(shiny.port = 3838, shiny.host = "0.0.0.0")

log_message("Starting Shiny app on http://localhost:3838")
log_message("Click 'Sign in with Google' to test OAuth flow")

# Run the app
shiny::runApp(".", launch.browser = FALSE)
