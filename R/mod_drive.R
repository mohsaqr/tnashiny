# ============================================================================
# Google Drive Module
# ============================================================================
# Handles all Google Drive operations:
# - Initialize folder structure
# - Save/Load analyses
# - Manage settings
# - List user's analyses
# ============================================================================

#' Initialize TNA folder structure in user's Google Drive
#' Creates: TNA_App/ with subdirectories for datasets, analyses, exports
#' @return List with folder IDs or NULL on error
initialize_drive_folders <- function() {
  message("=== INITIALIZING GOOGLE DRIVE FOLDERS ===")

  tryCatch({
    # First verify we have Drive access
    message("Verifying Drive access...")

    root_id <- NULL

    # Search for existing TNA_App folder - with drive.file scope,
    # we can only see files created by this app
    message("Searching for existing TNA_App folder...")

    existing <- tryCatch({
      result <- googledrive::drive_find(
        pattern = APP_FOLDER_NAME,
        type = "folder",
        n_max = 10
      )
      message("drive_find returned ", nrow(result), " results")
      result
    }, error = function(e) {
      message("drive_find error: ", e$message)
      # Return empty dribble
      googledrive::drive_find(n_max = 0)
    })

    # Check if we found our folder
    if (!is.null(existing) && nrow(existing) > 0) {
      # Look for exact match
      for (i in seq_len(nrow(existing))) {
        if (existing$name[i] == APP_FOLDER_NAME) {
          root_id <- as.character(existing$id[i])
          message("TNA_App folder found: ", root_id)
          break
        }
      }
    }

    # Create root folder if not found
    if (is.null(root_id)) {
      message("Creating TNA_App folder...")
      root_folder <- googledrive::drive_mkdir(APP_FOLDER_NAME)
      if (is.null(root_folder) || nrow(root_folder) == 0) {
        stop("Failed to create root folder")
      }
      root_id <- as.character(root_folder$id[1])
      message("Created TNA_App folder: ", root_id)
    }

    # Ensure subfolders exist
    subfolders <- c("datasets", "analyses", "exports")
    folder_ids <- list(root = root_id)

    for (subfolder in subfolders) {
      message("Checking subfolder: ", subfolder)
      folder_ids[[subfolder]] <- NULL

      # Search for subfolder within our root
      tryCatch({
        existing_sub <- googledrive::drive_find(
          pattern = subfolder,
          type = "folder",
          n_max = 20
        )

        if (!is.null(existing_sub) && nrow(existing_sub) > 0) {
          # Check each result for parent match
          for (i in seq_len(nrow(existing_sub))) {
            if (existing_sub$name[i] == subfolder) {
              tryCatch({
                file_info <- googledrive::drive_get(googledrive::as_id(existing_sub$id[i]))
                if (!is.null(file_info) && nrow(file_info) > 0) {
                  parents <- file_info$drive_resource[[1]]$parents
                  if (!is.null(parents) && length(parents) > 0 && root_id %in% parents) {
                    folder_ids[[subfolder]] <- as.character(existing_sub$id[i])
                    message("Found existing subfolder: ", subfolder)
                    break
                  }
                }
              }, error = function(e) {
                message("Error checking parent of ", subfolder, ": ", e$message)
              })
            }
          }
        }
      }, error = function(e) {
        message("Error searching for subfolder ", subfolder, ": ", e$message)
      })

      # Create if not found
      if (is.null(folder_ids[[subfolder]])) {
        message("Creating subfolder: ", subfolder)
        new_folder <- googledrive::drive_mkdir(
          name = subfolder,
          path = googledrive::as_id(root_id)
        )
        if (!is.null(new_folder) && nrow(new_folder) > 0) {
          folder_ids[[subfolder]] <- as.character(new_folder$id[1])
          message("Created subfolder: ", subfolder, " -> ", folder_ids[[subfolder]])
        } else {
          message("Warning: Could not create subfolder ", subfolder)
        }
      }
    }

    message("=== DRIVE INITIALIZATION COMPLETE ===")
    message("Root: ", folder_ids$root)
    message("Analyses: ", folder_ids$analyses)

    return(folder_ids)

  }, error = function(e) {
    message("Error initializing Drive folders: ", e$message)
    message("Full error: ", conditionMessage(e))
    return(NULL)
  })
}

#' Initialize settings file in user's Drive
#' @param root_folder_id The TNA_App folder ID
init_settings_file <- function(root_folder_id) {
  tryCatch({
    # Check if settings file exists
    existing <- googledrive::drive_find(
      q = sprintf(
        "name = '%s' and '%s' in parents and trashed = false",
        SETTINGS_FILE_NAME, root_folder_id
      ),
      n_max = 1
    )

    if (nrow(existing) == 0) {
      # Create default settings
      settings <- list(
        version = "1.0",
        created_at = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"),
        preferences = DEFAULT_PREFERENCES,
        recent = list()
      )

      # Write to temp file and upload
      temp_file <- tempfile(fileext = ".json")
      jsonlite::write_json(settings, temp_file, auto_unbox = TRUE, pretty = TRUE)

      googledrive::drive_upload(
        media = temp_file,
        path = googledrive::as_id(root_folder_id),
        name = SETTINGS_FILE_NAME,
        type = "application/json"
      )

      unlink(temp_file)
      message("Created settings file")
    }
  }, error = function(e) {
    message("Error creating settings file: ", e$message)
  })
}

#' Load user settings from Drive
#' @param folder_ids List of folder IDs from initialize_drive_folders
#' @return Settings list or default settings
load_user_settings <- function(folder_ids) {
  tryCatch({
    if (is.null(folder_ids)) return(DEFAULT_PREFERENCES)

    # Find settings file
    settings_file <- googledrive::drive_find(
      q = sprintf(
        "name = '%s' and '%s' in parents and trashed = false",
        SETTINGS_FILE_NAME, folder_ids$root
      ),
      n_max = 1
    )

    if (nrow(settings_file) > 0) {
      # Download and parse
      temp_file <- tempfile(fileext = ".json")
      googledrive::drive_download(
        file = googledrive::as_id(settings_file$id[1]),
        path = temp_file,
        overwrite = TRUE
      )

      settings <- jsonlite::read_json(temp_file)
      unlink(temp_file)

      return(settings)
    }

    return(list(preferences = DEFAULT_PREFERENCES, recent = list()))

  }, error = function(e) {
    message("Error loading settings: ", e$message)
    return(list(preferences = DEFAULT_PREFERENCES, recent = list()))
  })
}

#' Save user settings to Drive
#' @param folder_ids List of folder IDs
#' @param settings Settings list to save
save_user_settings <- function(folder_ids, settings) {
  tryCatch({
    if (is.null(folder_ids)) return(FALSE)

    # Find existing settings file
    settings_file <- googledrive::drive_find(
      q = sprintf(
        "name = '%s' and '%s' in parents and trashed = false",
        SETTINGS_FILE_NAME, folder_ids$root
      ),
      n_max = 1
    )

    # Write to temp file
    temp_file <- tempfile(fileext = ".json")
    settings$updated_at <- format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ")
    jsonlite::write_json(settings, temp_file, auto_unbox = TRUE, pretty = TRUE)

    if (nrow(settings_file) > 0) {
      # Update existing file
      googledrive::drive_update(
        file = googledrive::as_id(settings_file$id[1]),
        media = temp_file
      )
    } else {
      # Create new file
      googledrive::drive_upload(
        media = temp_file,
        path = googledrive::as_id(folder_ids$root),
        name = SETTINGS_FILE_NAME,
        type = "application/json"
      )
    }

    unlink(temp_file)
    return(TRUE)

  }, error = function(e) {
    message("Error saving settings: ", e$message)
    return(FALSE)
  })
}

#' Save analysis to Google Drive
#' @param folder_ids List of folder IDs
#' @param analysis_data List containing all analysis data to save
#' @param name User-provided name for the analysis
#' @param description User-provided description
#' @return List with success status and file info
save_analysis_to_drive <- function(folder_ids, analysis_data, name, description = "") {
  message("=== SAVE ANALYSIS TO DRIVE ===")
  message("Name: ", name)
  message("Folder IDs present: ", !is.null(folder_ids))

  tryCatch({
    if (is.null(folder_ids)) {
      message("ERROR: folder_ids is NULL")
      return(list(success = FALSE, error = "Drive not initialized. Please log out and log in again."))
    }

    message("Analyses folder ID: ", folder_ids$analyses)

    # Generate unique filename
    analysis_id <- generate_analysis_id()
    safe_name <- sanitize_filename(name)
    filename <- paste0(safe_name, "_", analysis_id, ".rds")
    message("Filename: ", filename)

    # Prepare analysis object
    save_obj <- list(
      # Metadata
      meta = list(
        id = analysis_id,
        name = name,
        description = description,
        created_at = Sys.time(),
        app_version = APP_VERSION
      ),

      # Analysis results
      tna_result = analysis_data$tna_result,
      centrality_result = analysis_data$centrality_result,
      community_result = analysis_data$community_result,
      cliques_result = analysis_data$cliques_result,
      bootstrap_result = analysis_data$bootstrap_result,

      # Data
      original_data = analysis_data$original,
      processed_data = analysis_data$data,

      # Settings
      settings = analysis_data$settings
    )

    # Save to temp file
    temp_file <- tempfile(fileext = ".rds")
    saveRDS(save_obj, temp_file)

    # Upload to Drive (omit type to let googledrive auto-detect)
    message("Uploading to Drive...")
    uploaded <- googledrive::drive_upload(
      media = temp_file,
      path = googledrive::as_id(folder_ids$analyses),
      name = filename
    )
    message("Upload complete: ", uploaded$id)

    unlink(temp_file)

    # Update recent in settings
    update_recent_analyses(folder_ids, list(
      file_id = uploaded$id,
      name = name,
      filename = filename,
      date = format(Sys.time(), "%Y-%m-%d"),
      type = analysis_data$settings$type
    ))

    return(list(
      success = TRUE,
      file_id = uploaded$id,
      filename = filename,
      name = name
    ))

  }, error = function(e) {
    message("Error saving analysis: ", e$message)
    return(list(success = FALSE, error = e$message))
  })
}

#' Update recent analyses in settings
#' @param folder_ids Folder IDs
#' @param analysis_info Info about the saved analysis
update_recent_analyses <- function(folder_ids, analysis_info) {
  tryCatch({
    settings <- load_user_settings(folder_ids)

    # Add to recent, keeping max 10
    if (is.null(settings$recent)) settings$recent <- list()

    settings$recent <- c(list(analysis_info), settings$recent)
    if (length(settings$recent) > 10) {
      settings$recent <- settings$recent[1:10]
    }

    save_user_settings(folder_ids, settings)
  }, error = function(e) {
    message("Error updating recent analyses: ", e$message)
  })
}

#' Load analysis from Google Drive
#' @param file_id Google Drive file ID
#' @return Analysis object or NULL
load_analysis_from_drive <- function(file_id) {
  tryCatch({
    temp_file <- tempfile(fileext = ".rds")

    googledrive::drive_download(
      file = googledrive::as_id(file_id),
      path = temp_file,
      overwrite = TRUE
    )

    analysis <- readRDS(temp_file)
    unlink(temp_file)

    return(analysis)

  }, error = function(e) {
    message("Error loading analysis: ", e$message)
    return(NULL)
  })
}

#' List all analyses in user's Drive
#' @param folder_ids Folder IDs
#' @return Data frame of analyses
list_analyses_from_drive <- function(folder_ids) {
  tryCatch({
    if (is.null(folder_ids)) {
      return(data.frame())
    }

    # Find all .rds files in analyses folder
    files <- googledrive::drive_find(
      q = sprintf(
        "'%s' in parents and name contains '.rds' and trashed = false",
        folder_ids$analyses
      ),
      orderBy = "modifiedTime desc"
    )

    if (nrow(files) == 0) {
      return(data.frame(
        id = character(),
        name = character(),
        modified = character(),
        size = character()
      ))
    }

    # Extract info
    result <- data.frame(
      id = files$id,
      name = gsub("_[0-9]{8}_[0-9]{6}_[a-z]{6}\\.rds$", "", files$name),
      filename = files$name,
      modified = sapply(files$drive_resource, function(x) {
        if (!is.null(x$modifiedTime)) x$modifiedTime else NA
      }),
      size = sapply(files$drive_resource, function(x) {
        if (!is.null(x$size)) as.numeric(x$size) else NA
      }),
      stringsAsFactors = FALSE
    )

    return(result)

  }, error = function(e) {
    message("Error listing analyses: ", e$message)
    return(data.frame())
  })
}

#' Delete analysis from Drive
#' @param file_id Google Drive file ID
#' @return TRUE on success
delete_analysis_from_drive <- function(file_id) {
  tryCatch({
    googledrive::drive_trash(googledrive::as_id(file_id))
    return(TRUE)
  }, error = function(e) {
    message("Error deleting analysis: ", e$message)
    return(FALSE)
  })
}

#' Export data to Drive (CSV, etc)
#' @param folder_ids Folder IDs
#' @param data Data to export
#' @param filename Filename
#' @param format Export format ("csv", "xlsx")
#' @return List with success status
export_to_drive <- function(folder_ids, data, filename, format = "csv") {
  tryCatch({
    if (is.null(folder_ids)) {
      return(list(success = FALSE, error = "Drive not initialized"))
    }

    temp_file <- tempfile(fileext = paste0(".", format))

    if (format == "csv") {
      write.csv(data, temp_file, row.names = FALSE)
      mime_type <- "text/csv"
    } else if (format == "xlsx") {
      rio::export(data, temp_file)
      mime_type <- "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    } else {
      return(list(success = FALSE, error = "Unsupported format"))
    }

    uploaded <- googledrive::drive_upload(
      media = temp_file,
      path = googledrive::as_id(folder_ids$exports),
      name = filename,
      type = mime_type
    )

    unlink(temp_file)

    return(list(success = TRUE, file_id = uploaded$id))

  }, error = function(e) {
    message("Error exporting: ", e$message)
    return(list(success = FALSE, error = e$message))
  })
}

#' Get shareable link for a file
#' @param file_id Google Drive file ID
#' @return Shareable URL or NULL
get_shareable_link <- function(file_id) {
  tryCatch({
    # Make file viewable by anyone with link
    googledrive::drive_share(
      file = googledrive::as_id(file_id),
      role = "reader",
      type = "anyone"
    )

    # Get the web view link
    file_info <- googledrive::drive_get(googledrive::as_id(file_id))
    link <- file_info$drive_resource[[1]]$webViewLink

    return(link)

  }, error = function(e) {
    message("Error getting shareable link: ", e$message)
    return(NULL)
  })
}
