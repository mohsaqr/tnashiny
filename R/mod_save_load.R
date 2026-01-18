# ============================================================================
# Save/Load Module
# ============================================================================
# Provides UI and server logic for saving and loading analyses
# ============================================================================

#' Save Dialog UI (Modal)
#' @param id Module namespace ID
saveDialogUI <- function(id) {
  ns <- NS(id)

  modalDialog(
    title = tagList(icon("cloud-arrow-up"), " Save Analysis to Google Drive"),
    size = "m",
    easyClose = TRUE,
    fade = TRUE,

    div(
      class = "save-dialog",

      textInput(
        ns("save_name"),
        "Analysis Name",
        placeholder = "Enter a name for your analysis"
      ),

      textAreaInput(
        ns("save_description"),
        "Description (optional)",
        placeholder = "Add notes or description...",
        rows = 3
      ),

      div(
        class = "save-options",
        checkboxInput(ns("include_data"), "Include original dataset", value = TRUE),
        checkboxInput(ns("include_results"), "Include all computed results", value = TRUE)
      ),

      div(
        class = "save-info",
        icon("info-circle"),
        span("Your analysis will be saved to your Google Drive in the TNA_App/analyses folder.")
      )
    ),

    footer = tagList(
      modalButton("Cancel"),
      actionButton(ns("do_save"), "Save to Drive", class = "btn-primary", icon = icon("cloud-arrow-up"))
    )
  )
}

#' Load Dialog UI (Modal)
#' @param id Module namespace ID
#' @param analyses_list Data frame of available analyses
loadDialogUI <- function(id, analyses_list) {
  ns <- NS(id)

  modalDialog(
    title = tagList(icon("folder-open"), " Load Analysis from Google Drive"),
    size = "l",
    easyClose = TRUE,
    fade = TRUE,

    div(
      class = "load-dialog",

      if (nrow(analyses_list) == 0) {
        div(
          class = "no-analyses",
          icon("folder-open", class = "fa-3x text-muted"),
          h4("No saved analyses found"),
          p("Save an analysis first to see it here.")
        )
      } else {
        tagList(
          div(
            class = "analyses-table-container",
            DTOutput(ns("analyses_table"))
          ),
          div(
            class = "selected-analysis-info",
            uiOutput(ns("selected_info"))
          )
        )
      }
    ),

    footer = if (nrow(analyses_list) > 0) {
      tagList(
        actionButton(ns("do_delete"), "Delete", class = "btn-danger", icon = icon("trash")),
        modalButton("Cancel"),
        actionButton(ns("do_load"), "Load Selected", class = "btn-primary", icon = icon("folder-open"))
      )
    } else {
      modalButton("Close")
    }
  )
}

#' Save/Load Module Server
#' @param id Module namespace ID
#' @param rv Reactive values containing analysis data
#' @param folder_ids Reactive containing folder IDs
#' @param input_values Reactive containing current input values
saveLoadModuleServer <- function(id, rv, folder_ids, input_values) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Store analyses list
    analyses_list <- reactiveVal(data.frame())

    # Selected analysis for loading
    selected_analysis <- reactiveVal(NULL)

    # Render analyses table
    output$analyses_table <- renderDT({
      df <- analyses_list()
      if (nrow(df) == 0) return(NULL)

      # Format for display
      display_df <- data.frame(
        Name = df$name,
        `Last Modified` = sapply(df$modified, format_date_display),
        Size = sapply(df$size, format_file_size),
        check.names = FALSE
      )

      datatable(
        display_df,
        selection = "single",
        options = list(
          pageLength = 5,
          dom = 'tp',
          ordering = TRUE,
          order = list(list(1, 'desc'))
        ),
        rownames = FALSE,
        class = "compact stripe"
      )
    })

    # Track selection
    observeEvent(input$analyses_table_rows_selected, {
      sel <- input$analyses_table_rows_selected
      if (length(sel) > 0) {
        df <- analyses_list()
        selected_analysis(df[sel, ])
      } else {
        selected_analysis(NULL)
      }
    })

    # Show selected analysis info
    output$selected_info <- renderUI({
      sel <- selected_analysis()
      if (is.null(sel)) {
        return(div(class = "text-muted", "Select an analysis to see details"))
      }

      div(
        class = "analysis-preview",
        h5(sel$name),
        p(
          tags$strong("File: "), sel$filename, tags$br(),
          tags$strong("Modified: "), format_date_display(sel$modified), tags$br(),
          tags$strong("Size: "), format_file_size(sel$size)
        )
      )
    })

    # Handle save
    observeEvent(input$do_save, {
      name <- trimws(input$save_name)

      if (name == "") {
        showNotification("Please enter a name for your analysis", type = "error")
        return()
      }

      if (is.null(rv$tna_result)) {
        showNotification("No analysis to save. Please run an analysis first.", type = "error")
        return()
      }

      # Show progress
      showNotification("Saving to Google Drive...", id = "save_progress", duration = NULL, type = "message")

      # Prepare data
      analysis_data <- list(
        tna_result = rv$tna_result,
        centrality_result = if (input$include_results) rv$centrality_result else NULL,
        community_result = if (input$include_results) rv$community_result else NULL,
        cliques_result = if (input$include_results) rv$cliques_result else NULL,
        bootstrap_result = if (input$include_results) rv$bootstrap_result else NULL,
        original = if (input$include_data) rv$original else NULL,
        data = rv$data,
        settings = input_values()
      )

      # Save
      result <- save_analysis_to_drive(
        folder_ids(),
        analysis_data,
        name,
        input$save_description
      )

      removeNotification("save_progress")

      if (result$success) {
        showNotification(
          paste("Analysis saved:", result$name),
          type = "message",
          duration = 3
        )
        removeModal()
      } else {
        showNotification(
          paste("Failed to save:", result$error),
          type = "error",
          duration = 5
        )
      }
    })

    # Handle load
    observeEvent(input$do_load, {
      sel <- selected_analysis()

      if (is.null(sel)) {
        showNotification("Please select an analysis to load", type = "error")
        return()
      }

      # Show progress
      showNotification("Loading from Google Drive...", id = "load_progress", duration = NULL, type = "message")

      # Load analysis
      analysis <- load_analysis_from_drive(sel$id)

      removeNotification("load_progress")

      if (!is.null(analysis)) {
        # Restore to reactive values
        rv$tna_result <- analysis$tna_result
        rv$centrality_result <- analysis$centrality_result
        rv$community_result <- analysis$community_result
        rv$cliques_result <- analysis$cliques_result
        rv$bootstrap_result <- analysis$bootstrap_result
        rv$original <- analysis$original_data
        rv$data <- analysis$processed_data

        showNotification(
          paste("Loaded:", analysis$meta$name),
          type = "message",
          duration = 3
        )
        removeModal()

        # Return loaded settings for UI update
        return(analysis$settings)
      } else {
        showNotification("Failed to load analysis", type = "error", duration = 5)
      }
    })

    # Handle delete
    observeEvent(input$do_delete, {
      sel <- selected_analysis()

      if (is.null(sel)) {
        showNotification("Please select an analysis to delete", type = "error")
        return()
      }

      # Confirm deletion
      showModal(modalDialog(
        title = "Confirm Delete",
        p("Are you sure you want to delete '", sel$name, "'?"),
        p(class = "text-muted", "This will move the file to your Google Drive trash."),
        footer = tagList(
          modalButton("Cancel"),
          actionButton(ns("confirm_delete"), "Delete", class = "btn-danger")
        )
      ))
    })

    # Confirm delete
    observeEvent(input$confirm_delete, {
      sel <- selected_analysis()

      if (!is.null(sel)) {
        success <- delete_analysis_from_drive(sel$id)

        if (success) {
          showNotification("Analysis deleted", type = "message")
          # Refresh list
          analyses_list(list_analyses_from_drive(folder_ids()))
          selected_analysis(NULL)
        } else {
          showNotification("Failed to delete analysis", type = "error")
        }
      }

      removeModal()
      # Re-open load dialog
      showModal(loadDialogUI(ns(""), analyses_list()))
    })

    # Return functions to trigger dialogs
    list(
      show_save_dialog = function() {
        showModal(saveDialogUI(id))
      },

      show_load_dialog = function() {
        # Refresh analyses list
        analyses_list(list_analyses_from_drive(folder_ids()))
        showModal(loadDialogUI(id, analyses_list()))
      },

      refresh_analyses = function() {
        analyses_list(list_analyses_from_drive(folder_ids()))
      }
    )
  })
}
