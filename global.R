# ============================================================================
# TNA Shiny App - Global Configuration
# ============================================================================
# Google OAuth and Drive Integration
# All user data stored in USER'S Google Drive - we store nothing
# ============================================================================

# Load environment variables from .Renviron
if (file.exists(".Renviron")) {
  readRenviron(".Renviron")
}

# Required packages
library(shiny)
library(shinydashboard)
library(DT)
library(tna)
library(bslib)
library(rio)
library(shinyjs)
library(shinyjqui)
library(googleAuthR)
library(googledrive)
library(gargle)
library(httr)
library(jsonlite)

# Define %||% operator (null coalescing)
`%||%` <- function(x, y) if (is.null(x) || length(x) == 0 || (is.character(x) && x == "")) y else x

# ============================================================================
# Google OAuth Configuration
# ============================================================================

# OAuth Client ID (from Google Cloud Console)
GOOGLE_CLIENT_ID <- "832405455907-e3i1gegnbfj6k5uspbvhes13m9v6gc0m.apps.googleusercontent.com"

# Client secret - check .Renviron or use empty for installed app flow
GOOGLE_CLIENT_SECRET <- Sys.getenv("GOOGLE_CLIENT_SECRET", "")

# OAuth scopes - minimal permissions
# drive.file = only access files created by this app
GOOGLE_SCOPES <- c(

"https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
  "https://www.googleapis.com/auth/drive.file"
)

# Configure googleAuthR
options(
  googleAuthR.client_id = GOOGLE_CLIENT_ID,
  googleAuthR.client_secret = GOOGLE_CLIENT_SECRET,
  googleAuthR.scopes.selected = GOOGLE_SCOPES,
  googleAuthR.webapp.client_id = GOOGLE_CLIENT_ID,
  googleAuthR.webapp.client_secret = GOOGLE_CLIENT_SECRET,
  gargle_oauth_email = TRUE,
  gargle_oob_default = FALSE
)

# ============================================================================
# App Constants
# ============================================================================

APP_NAME <- "TNA"
APP_VERSION <- "2.0.0"
APP_FOLDER_NAME <- "TNA_App"
SETTINGS_FILE_NAME <- ".tna_settings.json"

# Default plot margins
DEFAULT_MAR <- c(2.5, 2.5, 2.5, 2.5)

# Default preferences
DEFAULT_PREFERENCES <- list(
  default_type = "relative",
  default_layout = "circle",
  default_cut = 0.1,
  default_minimum = 0.05,
  default_vsize = 8,
  default_edge_label = 1,
  default_node_label = 1,
  skin = "purple"
)

# ============================================================================
# Helper Functions
# ============================================================================

#' Create a unique analysis ID
generate_analysis_id <- function() {
  paste0(
    format(Sys.time(), "%Y%m%d_%H%M%S"),
    "_",
    paste0(sample(letters, 6), collapse = "")
  )
}

#' Sanitize filename
sanitize_filename <- function(name) {
  # Remove special characters, keep alphanumeric, spaces, underscores, hyphens
  name <- gsub("[^[:alnum:] _-]", "", name)
  # Replace multiple spaces with single space
  name <- gsub("\\s+", " ", name)
  # Trim whitespace
  name <- trimws(name)
  # Limit length
  if (nchar(name) > 50) {
    name <- substr(name, 1, 50)
  }
  # Default if empty
  if (nchar(name) == 0) {
    name <- "Untitled"
  }
  return(name)
}

#' Format file size for display
format_file_size <- function(bytes) {
  if (is.null(bytes) || is.na(bytes)) return("Unknown")

  if (bytes < 1024) {
    return(paste(bytes, "B"))
  } else if (bytes < 1024^2) {
    return(paste(round(bytes / 1024, 1), "KB"))
  } else if (bytes < 1024^3) {
    return(paste(round(bytes / 1024^2, 1), "MB"))
  } else {
    return(paste(round(bytes / 1024^3, 1), "GB"))
  }
}

#' Format date for display
format_date_display <- function(date) {
  if (is.null(date) || is.na(date)) return("Unknown")
  format(as.POSIXct(date), "%b %d, %Y %H:%M")
}

# Set seed for reproducibility
set.seed(19)

# ============================================================================
# Source Modules
# ============================================================================

# Source all module files
module_files <- list.files("R", pattern = "\\.R$", full.names = TRUE)
for (f in module_files) {
  source(f)
}

message("TNA App v", APP_VERSION, " - Global configuration loaded")
message("Google OAuth Client ID: ", substr(GOOGLE_CLIENT_ID, 1, 20), "...")
