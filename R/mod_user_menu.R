# ============================================================================
# User Menu Module
# ============================================================================
# Provides the user dropdown menu in the header with:
# - User info display
# - My Analyses link
# - Settings
# - Logout
# ============================================================================

#' User Menu UI for Dashboard Header
#' @param id Module namespace ID
#' @param user_name User's display name
#' @param user_email User's email
#' @param user_picture URL to user's profile picture
userMenuUI <- function(id, user_name = "", user_email = "", user_picture = NULL) {
  ns <- NS(id)

  # Create user menu items
  tags$li(
    class = "dropdown user-menu-dropdown",

    # Dropdown toggle
    tags$a(
      href = "#",
      class = "dropdown-toggle",
      `data-toggle` = "dropdown",
      `aria-expanded` = "false",

      # User avatar or default icon
      if (!is.null(user_picture) && user_picture != "") {
        tags$img(
          src = user_picture,
          class = "user-image user-avatar",
          alt = "User"
        )
      } else {
        icon("user-circle", class = "user-avatar-icon")
      },

      # User name (hidden on small screens)
      tags$span(class = "hidden-xs user-name-display", user_name)
    ),

    # Dropdown menu
    tags$ul(
      class = "dropdown-menu",

      # User header
      tags$li(
        class = "user-header",
        if (!is.null(user_picture) && user_picture != "") {
          tags$img(
            src = user_picture,
            class = "img-circle",
            alt = "User",
            style = "width: 90px; height: 90px;"
          )
        } else {
          icon("user-circle", class = "fa-5x")
        },
        tags$p(
          user_name,
          tags$small(user_email)
        )
      ),

      # Menu items
      tags$li(
        class = "user-body",
        fluidRow(
          column(
            12,
            actionLink(ns("my_analyses"), tagList(icon("folder-open"), " My Analyses"), class = "user-menu-link"),
            tags$br(),
            actionLink(ns("settings"), tagList(icon("gear"), " Settings"), class = "user-menu-link"),
            tags$br(),
            tags$a(
              href = "https://drive.google.com",
              target = "_blank",
              class = "user-menu-link",
              icon("google-drive"), " Open Google Drive"
            )
          )
        )
      ),

      # Footer with logout
      tags$li(
        class = "user-footer",
        actionButton(
          ns("logout"),
          tagList(icon("sign-out-alt"), " Sign Out"),
          class = "btn btn-default btn-flat btn-block"
        )
      )
    )
  )
}

#' Simplified header buttons for Save/Load/Export
#' @param id Module namespace ID
headerButtonsUI <- function(id) {
  ns <- NS(id)

  tags$li(
    class = "dropdown header-buttons",
    tags$div(
      class = "header-btn-group",
      actionButton(
        ns("btn_save"),
        tagList(icon("cloud-arrow-up")),
        class = "btn-header",
        title = "Save to Drive"
      ),
      actionButton(
        ns("btn_load"),
        tagList(icon("folder-open")),
        class = "btn-header",
        title = "Load from Drive"
      ),
      actionButton(
        ns("btn_export"),
        tagList(icon("file-export")),
        class = "btn-header",
        title = "Export"
      )
    )
  )
}

#' User Menu Server
#' @param id Module namespace ID
#' @param auth Reactive auth state
#' @param save_load_handlers Save/Load handler functions
userMenuServer <- function(id, auth, save_load_handlers = NULL) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Handle logout
    observeEvent(input$logout, {
      showModal(modalDialog(
        title = "Sign Out",
        p("Are you sure you want to sign out?"),
        p(class = "text-muted", "Your analyses are safely stored in your Google Drive."),
        footer = tagList(
          modalButton("Cancel"),
          actionButton(ns("confirm_logout"), "Sign Out", class = "btn-danger")
        )
      ))
    })

    observeEvent(input$confirm_logout, {
      logout_user(auth)
      removeModal()
      # Reload the page to show login
      session$reload()
    })

    # Handle My Analyses click
    observeEvent(input$my_analyses, {
      if (!is.null(save_load_handlers)) {
        save_load_handlers$show_load_dialog()
      }
    })

    # Handle Settings click
    observeEvent(input$settings, {
      showModal(settingsDialogUI(ns("")))
    })

    # Handle Save button
    observeEvent(input$btn_save, {
      if (!is.null(save_load_handlers)) {
        save_load_handlers$show_save_dialog()
      }
    })

    # Handle Load button
    observeEvent(input$btn_load, {
      if (!is.null(save_load_handlers)) {
        save_load_handlers$show_load_dialog()
      }
    })

    # Handle Export button
    observeEvent(input$btn_export, {
      showModal(exportDialogUI(ns("")))
    })
  })
}

#' Settings Dialog UI
#' @param id Namespace ID
settingsDialogUI <- function(id) {
  ns <- NS(id)

  modalDialog(
    title = tagList(icon("gear"), " Settings"),
    size = "m",
    easyClose = TRUE,

    div(
      class = "settings-dialog",

      h4("Default Preferences"),
      p(class = "text-muted", "These settings will be applied when you start a new analysis."),

      selectInput(
        ns("pref_type"),
        "Default Analysis Type",
        choices = c("relative", "frequency", "co-occurrence"),
        selected = "relative"
      ),

      selectInput(
        ns("pref_layout"),
        "Default Layout",
        choices = c("circle", "spring"),
        selected = "circle"
      ),

      sliderInput(
        ns("pref_cut"),
        "Default Cut Value",
        min = 0, max = 1, value = 0.1, step = 0.01
      ),

      sliderInput(
        ns("pref_vsize"),
        "Default Node Size",
        min = 1, max = 20, value = 8, step = 0.5
      ),

      hr(),

      h4("Storage Info"),
      p(
        icon("google-drive"),
        " Your data is stored in: ",
        tags$strong("Google Drive / TNA_App")
      )
    ),

    footer = tagList(
      modalButton("Cancel"),
      actionButton(ns("save_settings"), "Save Settings", class = "btn-primary")
    )
  )
}

#' Export Dialog UI
#' @param id Namespace ID
exportDialogUI <- function(id) {
  ns <- NS(id)

  modalDialog(
    title = tagList(icon("file-export"), " Export Results"),
    size = "m",
    easyClose = TRUE,

    div(
      class = "export-dialog",

      h4("What to Export"),

      checkboxGroupInput(
        ns("export_items"),
        NULL,
        choices = c(
          "Transition Matrix" = "matrix",
          "Centrality Measures" = "centrality",
          "Initial Probabilities" = "initial",
          "Summary Statistics" = "summary"
        ),
        selected = c("matrix", "centrality")
      ),

      hr(),

      h4("Export Options"),

      radioButtons(
        ns("export_format"),
        "Format",
        choices = c("CSV" = "csv", "Excel" = "xlsx"),
        selected = "csv",
        inline = TRUE
      ),

      radioButtons(
        ns("export_destination"),
        "Destination",
        choices = c(
          "Download to computer" = "download",
          "Save to Google Drive" = "drive"
        ),
        selected = "download"
      )
    ),

    footer = tagList(
      modalButton("Cancel"),
      downloadButton(ns("do_export_download"), "Export", class = "btn-primary")
    )
  )
}
