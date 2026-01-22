# ============================================================================
# TNA Shiny App - Main Application
# ============================================================================
# Transition Network Analysis with Google OAuth and Drive Integration
# All user data stored in USER'S Google Drive
# ============================================================================

# Source global configuration and modules
source("global.R")

# ============================================================================
# UI
# ============================================================================

ui <- function(request) {
  tagList(
    useShinyjs(),
    tags$head(
      tags$link(rel = "stylesheet", type = "text/css", href = "custom.css"),
      tags$meta(name = "viewport", content = "width=device-width, initial-scale=1"),
      # Hide permutation menu by default (only shown in Group TNA mode)
      tags$style(HTML("a[data-value='permutation'] { display: none; }")),
      # JavaScript for session persistence (localStorage for cross-session)
      tags$script(HTML("
        // Store auth data in localStorage (persists across browser sessions)
        Shiny.addCustomMessageHandler('storeAuth', function(data) {
          try {
            localStorage.setItem('tna_auth', JSON.stringify(data));
          } catch(e) {
            console.error('Failed to store auth:', e);
          }
        });

        // Clear auth data
        Shiny.addCustomMessageHandler('clearAuth', function(data) {
          try {
            localStorage.removeItem('tna_auth');
          } catch(e) {
            console.error('Failed to clear auth:', e);
          }
        });

        // On page load, check for stored auth and send to Shiny
        $(document).on('shiny:connected', function() {
          try {
            var stored = localStorage.getItem('tna_auth');
            if (stored) {
              var parsed = JSON.parse(stored);
              Shiny.setInputValue('stored_auth', parsed, {priority: 'event'});
            } else {
              Shiny.setInputValue('stored_auth', null, {priority: 'event'});
            }
          } catch(e) {
            console.error('Failed to restore session:', e);
            // Clear corrupted data
            try { localStorage.removeItem('tna_auth'); } catch(e2) {}
            Shiny.setInputValue('stored_auth', null, {priority: 'event'});
          }
        });
      "))
    ),

    # Main UI - switches between login and dashboard
    uiOutput("main_ui")
  )
}

# ============================================================================
# Server
# ============================================================================

server <- function(input, output, session) {
  # --------------------------------------------------------------------------
  # Authentication State
  # --------------------------------------------------------------------------

  auth <- reactiveValues(
    logged_in = FALSE,
    user_email = NULL,
    user_name = NULL,
    user_picture = NULL,
    access_token = NULL
  )

  # Google Drive folder IDs
  folder_ids <- reactiveVal(NULL)

  # User settings from Drive
  user_settings <- reactiveVal(list(preferences = DEFAULT_PREFERENCES))

  # --------------------------------------------------------------------------
  # Session Restoration from Browser Storage
  # --------------------------------------------------------------------------

  observeEvent(input$stored_auth,
    {
      stored <- input$stored_auth
      if (!is.null(stored) && !auth$logged_in) {
        message("=== RESTORING SESSION FROM STORAGE ===")

        tryCatch(
          {
            # Restore auth state
            auth$logged_in <- TRUE
            auth$user_email <- stored$user_email
            auth$user_name <- stored$user_name
            auth$user_picture <- stored$user_picture
            auth$access_token <- stored$access_token

            # Reconfigure googledrive
            configure_drive_token(stored$access_token, stored$refresh_token)

            message("Session restored for: ", auth$user_email)

            # Restore Drive folders
            if (!is.null(stored$folder_ids)) {
              folder_ids(stored$folder_ids)
              message("Drive folders restored")
            } else {
              # Re-initialize if not stored
              folders <- initialize_drive_folders()
              folder_ids(folders)
            }
          },
          error = function(e) {
            message("Session restore failed: ", e$message)
            # Clear invalid stored auth
            session$sendCustomMessage("clearAuth", list())
          }
        )
      }
    },
    ignoreNULL = FALSE,
    once = TRUE
  )

  # --------------------------------------------------------------------------
  # OAuth Callback Handler
  # --------------------------------------------------------------------------

  observe({
    query <- parseQueryString(session$clientData$url_search)

    message("=== URL Query Check ===")
    message("URL search: ", session$clientData$url_search)
    message("Has code: ", !is.null(query$code))
    message("Already logged in: ", auth$logged_in)

    if (!is.null(query$code) && !auth$logged_in) {
      message("=== OAUTH CALLBACK RECEIVED ===")
      message("Auth code: ", substr(query$code, 1, 20), "...")

      tryCatch(
        {
          # Exchange code for token
          message("Exchanging code for token...")
          token <- exchange_code_for_token(query$code, session)

          if (!is.null(token)) {
            # Get user info
            user_info <- get_user_info(token$access_token)

            if (!is.null(user_info)) {
              auth$logged_in <- TRUE
              auth$user_email <- user_info$email
              auth$user_name <- user_info$name %||% user_info$email
              auth$user_picture <- user_info$picture
              auth$access_token <- token$access_token

              # Configure googledrive with refresh token if available
              configure_drive_token(token$access_token, token$refresh_token)

              # Clear URL
              updateQueryString("?", mode = "replace", session = session)

              showNotification(
                paste("Welcome,", auth$user_name),
                type = "message",
                duration = 3
              )

              # Initialize Drive folders
              showNotification("Setting up your Google Drive...", id = "drive_init", duration = NULL)
              folders <- initialize_drive_folders()
              folder_ids(folders)
              removeNotification("drive_init")

              if (!is.null(folders)) {
                # Load user settings
                settings <- load_user_settings(folders)
                user_settings(settings)
                showNotification("Google Drive ready!", type = "message", duration = 2)

                # Store auth in browser for session persistence
                session$sendCustomMessage("storeAuth", list(
                  user_email = auth$user_email,
                  user_name = auth$user_name,
                  user_picture = auth$user_picture,
                  access_token = token$access_token,
                  refresh_token = token$refresh_token,
                  folder_ids = folders
                ))
              }
            }
          }
        },
        error = function(e) {
          showNotification(
            paste("Login failed:", e$message),
            type = "error",
            duration = 5
          )
          updateQueryString("?", mode = "replace", session = session)
        }
      )
    }
  })

  # --------------------------------------------------------------------------
  # Main UI Rendering
  # --------------------------------------------------------------------------

  output$main_ui <- renderUI({
    tryCatch(
      {
        if (auth$logged_in) {
          # Show main dashboard
          main_dashboard_ui(auth$user_name, auth$user_email, auth$user_picture)
        } else {
          # Show login page
          login_page_ui()
        }
      },
      error = function(e) {
        message("ERROR in main_ui: ", e$message)
        div(
          style = "padding: 50px; text-align: center;",
          h2("Error Loading Application"),
          p("An error occurred while loading the application."),
          p(style = "color: red;", e$message),
          actionButton("reload_app", "Reload Application",
            class = "btn btn-primary",
            onclick = "localStorage.removeItem('tna_auth'); location.reload();"
          )
        )
      }
    )
  })

  # --------------------------------------------------------------------------
  # Login Page
  # --------------------------------------------------------------------------

  login_page_ui <- function() {
    div(
      class = "login-page",
      div(
        class = "login-container",
        div(
          class = "login-box",
          div(
            class = "login-header",
            img(src = "logo.png", height = "80", width = "73", alt = "TNA Logo"),
            h1("Transition Network Analysis"),
            p(class = "login-subtitle", "Analyze transition networks with ease")
          ),
          div(
            class = "login-features",
            div(class = "feature-item", icon("chart-bar"), span("Comprehensive Analysis")),
            div(class = "feature-item", icon("circle-nodes"), span("Network Visualization")),
            div(class = "feature-item", icon("cloud"), span("Cloud Storage"))
          ),
          div(
            class = "privacy-note",
            icon("shield-halved"),
            p("Your data stays in YOUR Google Drive. We store nothing.")
          ),
          div(
            class = "login-button-container",
            actionButton(
              "google_signin",
              label = tagList(
                tags$img(
                  src = "https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg",
                  height = "20",
                  style = "margin-right: 10px; vertical-align: middle;"
                ),
                "Sign in with Google"
              ),
              class = "btn-google-signin",
              onclick = "console.log('Button clicked!'); alert('Button works! Redirecting to Google...');"
            )
          ),
          div(
            class = "login-footer",
            p(
              "By signing in, you agree to allow TNA to create files in your Google Drive.",
              tags$br(),
              tags$a(href = "https://sonsoles.me/tna", target = "_blank", "Learn more about TNA")
            )
          )
        )
      )
    )
  }

  # Handle Google Sign-In
  observeEvent(input$google_signin, {
    message("=== SIGN IN BUTTON CLICKED ===")
    message("Building auth URL...")

    tryCatch(
      {
        auth_url <- build_auth_url(session)
        message("Auth URL: ", substr(auth_url, 1, 100), "...")
        message("Redirecting to Google...")
        runjs(sprintf('window.location.href = "%s";', auth_url))
      },
      error = function(e) {
        message("ERROR building auth URL: ", e$message)
        showNotification(paste("Error:", e$message), type = "error")
      }
    )
  })

  # --------------------------------------------------------------------------
  # Main Dashboard UI
  # --------------------------------------------------------------------------

  main_dashboard_ui <- function(user_name, user_email, user_picture) {
    # Build header with user menu
    db_header <- dashboardHeader(
      title = "TNA",
      tags$li(
        class = "dropdown user user-menu",
        tags$a(
          href = "#", class = "dropdown-toggle", `data-toggle` = "dropdown",
          if (!is.null(user_picture) && user_picture != "") {
            tags$img(src = user_picture, class = "user-image", alt = "User")
          } else {
            icon("user-circle", class = "user-image")
          },
          tags$span(class = "hidden-xs", user_name)
        ),
        tags$ul(
          class = "dropdown-menu",
          tags$li(
            class = "user-header bg-purple",
            if (!is.null(user_picture) && user_picture != "") {
              tags$img(src = user_picture, class = "img-circle", alt = "User")
            } else {
              tags$div(icon("user-circle", class = "fa-4x"), style = "color: white;")
            },
            tags$p(user_name, tags$small(user_email))
          ),
          tags$li(
            class = "user-body",
            fluidRow(
              column(12,
                align = "center",
                actionLink("menu_my_analyses", tagList(icon("folder-open"), " My Analyses")),
                tags$br(),
                actionLink("menu_open_drive", tagList(icon("google-drive"), " Open TNA Folder"))
              )
            )
          ),
          tags$li(
            class = "user-footer",
            actionButton("logout_btn", tagList(icon("sign-out-alt"), " Sign Out"),
              class = "btn btn-default btn-flat btn-block"
            )
          )
        )
      )
    )

    # Add logo to header (safely modify structure)
    tryCatch(
      {
        logo <- tags$span(
          tags$a(
            href = "https://sonsoles.me/tna",
            tags$img(src = "logo.png", height = "44", width = "40")
          ),
          "TNA"
        )
        if (length(db_header$children) >= 2 && !is.null(db_header$children[[2]])) {
          db_header$children[[2]]$children <- logo
        }
      },
      error = function(e) {
        message("Could not modify header logo: ", e$message)
      }
    )

    # Build full dashboard
    dashboardPage(
      skin = "purple",
      title = "TNA",
      db_header,
      dashboardSidebar(
        sidebarMenu(
          id = "sidebar_menu",
          menuItem("About TNA", tabName = "about", icon = icon("circle-info")),
          menuItem("Input Data", tabName = "input", icon = icon("table"), selected = TRUE),
          menuItem("Summary results", tabName = "results", icon = icon("chart-bar")),
          menuItem("Visualization", tabName = "tna_plot", icon = icon("circle-nodes")),
          menuItem("Sequences", tabName = "sequences", icon = icon("list-ol")),
          menuItem("Frequencies", tabName = "frequencies", icon = icon("chart-column")),
          menuItem("Associations", tabName = "associations", icon = icon("link")),
          menuItem("Centrality Measures", tabName = "centrality", icon = icon("chart-line")),
          menuItem("Community Detection", tabName = "communities", icon = icon("users")),
          menuItem("Edge Betweenness", tabName = "edgebet", icon = icon("people-arrows")),
          menuItem("Cliques", tabName = "cliques", icon = icon("sitemap")),
          menuItem("Comparison", tabName = "comparison", icon = icon("balance-scale")),
          menuItem("Group Networks", tabName = "group_networks", icon = icon("object-group")),
          menuItem("Bootstrap", tabName = "bootstrap", icon = icon("check-circle")),
          menuItem("Permutation", tabName = "permutation", icon = icon("shuffle"))
        )
      ),
      dashboardBody(
        tags$html(lang = "en"),
        tags$link(rel = "stylesheet", type = "text/css", href = "custom.css"),

        # Top-level mode tabs (TNA vs Group TNA)
        div(
          class = "mode-tabs",
          style = "padding: 10px 15px; background: #f4f4f4; border-bottom: 1px solid #ddd; margin-bottom: 10px;",
          # Mode selector tabs
          tags$span(
            actionLink("mode_tna", "TNA", style = "font-size: 18px; font-weight: bold; color: #3c8dbc; margin-right: 20px; text-decoration: none;"),
            actionLink("mode_group_tna", "Group TNA", style = "font-size: 18px; font-weight: bold; color: #999; margin-right: 30px; text-decoration: none;")
          ),
          # Save/Load/Export buttons
          actionButton("btn_save", tagList(icon("cloud-arrow-up"), " Save"), class = "btn btn-primary btn-sm", style = "margin-right: 5px;"),
          actionButton("btn_load", tagList(icon("folder-open"), " Load"), class = "btn btn-info btn-sm", style = "margin-right: 5px;"),
          actionButton("btn_export", tagList(icon("file-export"), " Export"), class = "btn btn-default btn-sm")
        ),

        # All tab items from original app
        tabItems(
          # About Tab
          tabItem(
            tabName = "about",
            h2("Transition Network Analysis (TNA)"),
            p(
              "Transition Network Analysis (TNA) is designed for analyzing transition networks,
              providing methods for examining sequences, identifying communities, calculating
              centrality measures, and visualizing network dynamics. TNA was presented for the
              first time at the Learning Analytics & Knowledge conference (2025).",
              tags$a("Check out our paper", href = "https://dl.acm.org/doi/10.1145/3706468.3706513"), "."
            ),
            h3("Usage"),
            p(
              "TNA offers a set of tools for researchers and analysts working with transition networks.",
              tags$a("Check the package documentation", href = "https://sonsoles.me/tna/"), "."
            ),
            tags$ul(
              tags$li(tags$b("Transition Analysis"), ": Understand transitions and connections in sequential data."),
              tags$li(tags$b("Community Detection"), ": Apply multiple algorithms to find community structures."),
              tags$li(tags$b("Centrality Measures"), ": Calculate centrality measures to identify key nodes."),
              tags$li(tags$b("Visualization"), ": Generate interactive and static plots.")
            ),
            img(src = "TNA.png", style = "width: 500px; max-width: 100%;"),
            h3("Tutorials"),
            tags$ul(
              tags$li(tags$a(href = "https://lamethods.org/book2/chapters/ch15-tna/ch15-tna.html", "Basic TNA tutorial", target = "_blank")),
              tags$li(tags$a(href = "https://lamethods.org/book2/chapters/ch16-ftna/ch16-ftna.html", "Frequency-based TNA tutorial", target = "_blank")),
              tags$li(tags$a(href = "https://lamethods.org/book2/chapters/ch17-tna-clusters/ch17-tna-clusters.html", "Clustering tutorial", target = "_blank"))
            ),
            h3("Citation"),
            p("Please cite the tna package if you use it in your research:"),
            tags$blockquote("Lopez-Pernas S, Saqr M, Tikka S (2024). tna: An R package for Transition Network Analysis.")
          ),

          # Input Data Tab
          tabItem(
            tabName = "input",
            fluidRow(
              column(
                width = 3,
                fluidRow(
                  box(
                    title = "Data Input", width = 12,
                    radioButtons("inputType", "Input Type:",
                      selected = character(0),
                      choices = c(
                        "Sample data" = "sample", "Sequence Data" = "sequence",
                        "Long Data" = "long", "Transition Matrix" = "matrix"
                      )
                    ),
                    conditionalPanel(
                      "input.inputType == 'sequence'",
                      fileInput("fileInput", "Upload data file (sequence or wide data)")
                    ),
                    conditionalPanel(
                      "input.inputType == 'long'",
                      fileInput("longInput", "Upload long data"),
                      selectInput("longAction", "Action:", choices = NULL, selectize = FALSE),
                      selectInput("longActor", "Actor:", choices = NULL, selectize = FALSE),
                      selectInput("longTime", "Time:", choices = NULL, selectize = FALSE),
                      selectInput("longOrder", "Order:", choices = NULL, selectize = FALSE),
                      numericInput("longThreshold", "Threshold:", min = 0, value = 900, step = 1),
                      textInput("longDate", "Date format:", placeholder = "Not mandatory")
                    ),
                    conditionalPanel(
                      "input.inputType == 'matrix'",
                      fileInput("matrixInput", "Upload transition matrix")
                    ),
                    selectInput("type", "Analysis Type:", choices = c("relative", "frequency", "co-occurrence")),
                    # Group selector - only visible in Group TNA mode
                    div(
                      id = "group_input_container", style = "display: none;",
                      selectInput("gm_groupVar", "Group:", choices = NULL)
                    ),
                    actionButton("analyze", "Analyze", class = "btn-primary")
                  )
                )
              ),
              column(
                width = 9,
                fluidRow(
                  conditionalPanel(
                    "!(input.inputType)",
                    fluidRow(box(
                      width = 12, title = "Welcome to TNA!",
                      fluidRow(column(12, p("Select the format of your data on the left panel or use our example data."))),
                      fluidRow(
                        column(
                          4, span("Sequence Data", class = "datatype"),
                          img(src = "wide.png", width = "100%", class = "thumb"),
                          p("Wide-format data stores each time point in a separate column.")
                        ),
                        column(
                          4, span("Long Data", class = "datatype"),
                          img(src = "long.png", width = "100%", class = "thumb"),
                          p("Long-format data stacks repeated measurements in rows.")
                        ),
                        column(
                          4, span("Transition Matrix", class = "datatype"),
                          img(src = "matrix.png", width = "100%", class = "thumb"),
                          p("You can also upload directly a transition probability matrix.")
                        )
                      )
                    ))
                  ),
                  conditionalPanel(
                    "input.inputType",
                    box(
                      title = "Data Preview", width = 12,
                      DTOutput("dataPreview"),
                      conditionalPanel(
                        "input.inputType != 'sample' & !input.dataPreview_state",
                        span(icon("circle-info", class = "text-info"), "No data selected yet")
                      ),
                      tags$br(), uiOutput("tnaModel")
                    )
                  )
                )
              )
            )
          ),

          # Results Tab
          tabItem(
            tabName = "results",
            fluidRow(
              box(
                width = 3,
                div(
                  class = "box-header-with-export",
                  h3(class = "box-title", "Summary Statistics"),
                  tableExportButtons("summaryStats")
                ),
                tableOutput("summaryStats")
              ),
              box(
                width = 4,
                div(
                  class = "box-header-with-export",
                  h3(class = "box-title", "Initial Probabilities"),
                  tableExportButtons("initialProbs")
                ),
                DTOutput("initialProbs")
              ),
              box(
                width = 5,
                div(
                  class = "box-header-with-export",
                  h3(class = "box-title", "Transition Matrix"),
                  tableExportButtons("transitionMatrix")
                ),
                div(class = "responsive-table", DTOutput("transitionMatrix"))
              )
            )
          ),

          # Visualization Tab
          tabItem(
            tabName = "tna_plot",
            fluidRow(
              column(
                width = 3,
                fluidRow(box(
                  title = "Settings", width = 12,
                  sliderInput("cut", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                  sliderInput("minimum", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                  sliderInput("edge.label", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                  sliderInput("vsize", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                  sliderInput("node.label", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                  selectInput("layout", "Layout", choices = c("circle", "spring"), selected = "circle")
                ))
              ),
              column(
                width = 9,
                fluidRow(box(
                  width = 12,
                  div(
                    class = "box-header-with-export",
                    h3(class = "box-title", "Visualization"),
                    plotExportButtons("tnaPlot")
                  ),
                  div(jqui_resizable(plotOutput("tnaPlot", width = "600px", height = "600px"),
                    options = list(ghost = TRUE, helper = "resizable-helper")
                  ), align = "center")
                ))
              )
            )
          ),

          # Sequences Tab
          tabItem(
            tabName = "sequences",
            conditionalPanel(
              "input.inputType != 'matrix'",
              fluidRow(
                column(
                  width = 3,
                  fluidRow(box(
                    title = "Sequence Plot Settings", width = 12,
                    selectInput("seqPlotType", "Plot Type:",
                      choices = c("Sequence Index" = "index", "Distribution" = "distribution"),
                      selected = "index"
                    ),
                    conditionalPanel(
                      "input.seqPlotType == 'distribution'",
                      selectInput("seqScale", "Scale:",
                        choices = c("Proportion" = "proportion", "Count" = "count"),
                        selected = "proportion"
                      ),
                      selectInput("seqGeom", "Geometry:",
                        choices = c("Bar" = "bar", "Area" = "area"),
                        selected = "bar"
                      )
                    ),
                    selectInput("seqGroup", "Group by:", choices = NULL),
                    checkboxInput("seqIncludeNA", "Include NA values", value = FALSE),
                    checkboxInput("seqShowN", "Show sample size (n)", value = TRUE),
                    numericInput("seqTick", "X-axis tick interval:", value = 5, min = 1, max = 20),
                    numericInput("seqNcol", "Number of columns:", value = 2, min = 1, max = 4),
                    textInput("seqTitle", "Plot title:", placeholder = "Optional title"),
                    textInput("seqXlab", "X-axis label:", value = "Time"),
                    textInput("seqYlab", "Y-axis label:", placeholder = "Auto")
                  ))
                ),
                column(
                  width = 9,
                  fluidRow(box(
                    width = 12,
                    div(
                      class = "box-header-with-export",
                      h3(class = "box-title", "Sequence Visualization"),
                      plotExportButtons("seqPlot")
                    ),
                    div(jqui_resizable(plotOutput("seqPlot", width = "800px", height = "600px"),
                      options = list(ghost = TRUE, helper = "resizable-helper")
                    ), align = "center")
                  ))
                )
              )
            ),
            conditionalPanel(
              "input.inputType == 'matrix'",
              box(span(
                icon("circle-info", class = "text-danger"),
                "Sequence plots require sequence or long data format, not a transition matrix"
              ), width = 7)
            )
          ),

          # Frequencies Tab
          tabItem(
            tabName = "frequencies",
            fluidRow(
              column(
                width = 3,
                fluidRow(box(
                  title = "Frequency Plot Settings", width = 12,
                  sliderInput("freqWidth", "Bar width:", min = 0.1, max = 1, value = 0.7, step = 0.1),
                  checkboxInput("freqShowLabel", "Show frequency labels", value = TRUE),
                  sliderInput("freqHjust", "Label position:", min = 0, max = 2, value = 1.2, step = 0.1)
                ))
              ),
              column(
                width = 9,
                fluidRow(box(
                  width = 12,
                  div(
                    class = "box-header-with-export",
                    h3(class = "box-title", "State Frequencies"),
                    plotExportButtons("freqPlot")
                  ),
                  div(jqui_resizable(plotOutput("freqPlot", width = "700px", height = "500px"),
                    options = list(ghost = TRUE, helper = "resizable-helper")
                  ), align = "center")
                ))
              )
            )
          ),

          # Associations Tab
          tabItem(
            tabName = "associations",
            fluidRow(
              column(
                width = 3,
                fluidRow(box(
                  title = "Association Plot Settings", width = 12,
                  sliderInput("assocCut", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                  sliderInput("assocMinimum", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                  sliderInput("assocEdgeLabel", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                  sliderInput("assocVsize", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                  sliderInput("assocNodeLabel", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                  selectInput("assocLayout", "Layout", choices = c("circle", "spring"), selected = "circle")
                ))
              ),
              column(
                width = 9,
                fluidRow(box(
                  width = 12,
                  div(
                    class = "box-header-with-export",
                    h3(class = "box-title", "Association Network"),
                    plotExportButtons("assocPlot")
                  ),
                  div(jqui_resizable(plotOutput("assocPlot", width = "600px", height = "600px"),
                    options = list(ghost = TRUE, helper = "resizable-helper")
                  ), align = "center")
                ))
              )
            )
          ),

          # Centrality Tab
          tabItem(
            tabName = "centrality",
            fluidRow(box(fluidRow(
              column(width = 6, selectInput("centralitiesChoice", "Centralities",
                multiple = TRUE,
                choices = c(
                  "OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                  "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"
                ),
                selected = c(
                  "OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                  "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"
                )
              )),
              column(
                width = 2, tags$label("Properties"),
                checkboxInput("loops", "Loops?", value = FALSE),
                checkboxInput("normalize", "Normalize?", value = FALSE), class = "checkboxcentralities"
              ),
              column(width = 2, numericInput("nColsCentralities", "Columns", 3, min = 1, max = 9, step = 1))
            ), width = 12)),
            fluidRow(box(
              width = 12,
              div(
                class = "box-header-with-export",
                h3(class = "box-title", "Centrality Measures"),
                div(
                  style = "display: flex; gap: 10px;",
                  span("Table:", style = "color: #666; font-size: 0.9em;"), tableExportButtons("centralityPrint"),
                  span("Plot:", style = "color: #666; font-size: 0.9em; margin-left: 15px;"), plotExportButtons("centralityPlot")
                )
              ),
              div(tableOutput("centralityPrint"), align = "center", width = 12),
              div(jqui_resizable(plotOutput("centralityPlot", width = "800px", height = "800px"),
                options = list(ghost = TRUE, helper = "resizable-helper")
              ), align = "center", width = 12)
            ))
          ),

          # Communities Tab
          tabItem(
            tabName = "communities",
            fluidRow(
              column(width = 3, fluidRow(
                box(
                  title = "Community Detection Settings", width = 12,
                  selectInput("communityAlgorithm", "Choose Algorithm:", choices = "spinglass"),
                  numericInput("gamma", "Gamma:", value = 1, min = 0, max = 100)
                ),
                box(
                  title = "Plotting Settings", width = 12,
                  sliderInput("cutCom", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                  sliderInput("minimumCom", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                  sliderInput("edge.labelCom", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                  sliderInput("vsizeCom", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                  sliderInput("node.labelCom", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                  selectInput("layoutCom", "Layout", choices = c("circle", "spring"), selected = "circle")
                )
              )),
              box(
                width = 9,
                div(
                  class = "box-header-with-export",
                  h3(class = "box-title", "Community Detection Results"),
                  plotExportButtons("communityPlot")
                ),
                div(jqui_resizable(plotOutput("communityPlot", width = "600px", height = "600px"),
                  options = list(ghost = TRUE, helper = "resizable-helper")
                ), align = "center", width = 12)
              )
            )
          ),

          # Edge Betweenness Tab
          tabItem(
            tabName = "edgebet",
            fluidRow(
              column(width = 3, fluidRow(box(
                title = "Settings", width = 12,
                sliderInput("cutEbet", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                sliderInput("minimumEbet", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                sliderInput("edge.labelEbet", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                sliderInput("vsizeEbet", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                sliderInput("node.labelEbet", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                selectInput("layoutEbet", "Layout", choices = c("circle", "spring"), selected = "circle")
              ))),
              column(width = 9, fluidRow(box(
                width = 12,
                div(
                  class = "box-header-with-export",
                  h3(class = "box-title", "Edge Betweenness"),
                  plotExportButtons("edgeBetPlot")
                ),
                div(jqui_resizable(plotOutput("edgeBetPlot", width = "600px", height = "600px"),
                  options = list(ghost = TRUE, helper = "resizable-helper")
                ), align = "center")
              )))
            )
          ),

          # Cliques Tab
          tabItem(
            tabName = "cliques",
            fluidRow(
              column(width = 3, fluidRow(
                box(
                  title = "Clique Settings", width = 12,
                  numericInput("cliqueSize", "Clique Size (n):", value = 3, min = 2, max = 10),
                  numericInput("cliqueThreshold", "Threshold:", value = 0, min = 0, max = 1, step = 0.05),
                  actionButton("findCliques", "Find Cliques", class = "btn-primary")
                ),
                box(
                  title = "Plotting Settings", width = 12,
                  sliderInput("cutClique", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                  sliderInput("minimumClique", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                  sliderInput("edge.labelClique", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                  sliderInput("vsizeClique", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                  sliderInput("node.labelClique", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                  selectInput("layoutClique", "Layout", choices = c("circle", "spring"), selected = "circle")
                )
              )),
              column(width = 9, fluidRow(box(
                width = 12,
                div(
                  class = "box-header-with-export",
                  h3(class = "box-title", "Cliques Found"),
                  plotExportButtons("cliquesPlot")
                ),
                selectInput("cliqueSelect", "Choose Clique:", choices = NULL, width = "30%"),
                div(jqui_resizable(plotOutput("cliquesPlot"),
                  options = list(ghost = TRUE, helper = "resizable-helper")
                ), align = "center", width = 12)
              )))
            )
          ),

          # Comparison Tab
          tabItem(
            tabName = "comparison",
            conditionalPanel(
              "(input.inputType == 'long') | (input.inputType == 'sample')",
              fluidRow(
                column(width = 3, fluidRow(
                  box(
                    title = "Comparison Settings", width = 12,
                    selectInput("compareSelect", "Choose grouping column:", choices = NULL),
                    selectInput("group1", "Choose group 1:", choices = NULL),
                    selectInput("group2", "Choose group 2:", choices = NULL),
                    input_switch("compare_sig", "Permutation test"),
                    conditionalPanel(
                      "input.compare_sig",
                      numericInput("iterPerm", "Iteration:", min = 0, max = 10000, value = 1000, step = 100),
                      numericInput("levelPerm", "Level:", min = 0, max = 1, value = 0.05, step = 0.01),
                      input_switch("pairedPerm", "Paired test")
                    )
                  ),
                  box(
                    title = "Plotting Settings", width = 12,
                    sliderInput("cutGroup", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                    sliderInput("minimumGroup", "Minimum Value", min = 0, max = 1, value = 0, step = 0.01),
                    sliderInput("edge.labelGroup", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                    sliderInput("vsizeGroup", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                    sliderInput("node.labelGroup", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                    selectInput("layoutGroup", "Layout", choices = c("circle", "spring"), selected = "circle")
                  )
                )),
                column(width = 9, fluidRow(
                  tabBox(
                    id = "tabset1", width = 12,
                    tabPanel(
                      "Difference",
                      div(
                        class = "box-header-with-export", style = "margin-bottom: 10px;",
                        span("Export:", style = "color: #666;"), plotExportButtons("comparisonPlot")
                      ),
                      div(jqui_resizable(plotOutput("comparisonPlot", width = "600px", height = "600px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")
                      ), align = "center")
                    ),
                    tabPanel(
                      "Mosaic",
                      div(
                        class = "box-header-with-export", style = "margin-bottom: 10px;",
                        span("Export:", style = "color: #666;"), plotExportButtons("mosaicPlot")
                      ),
                      div(jqui_resizable(plotOutput("mosaicPlot", width = "1400px", height = "900px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")
                      ), align = "center")
                    ),
                    tabPanel(
                      "Centralities",
                      fluidRow(box(fluidRow(
                        column(width = 6, selectInput("centralitiesChoiceGroup", "Centralities",
                          multiple = TRUE,
                          choices = c(
                            "OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                            "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"
                          ),
                          selected = c(
                            "OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                            "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"
                          )
                        )),
                        column(
                          width = 2, tags$label("Properties"),
                          checkboxInput("loopsGroup", "Loops?", value = FALSE),
                          checkboxInput("normalizeGroup", "Normalize?", value = FALSE), class = "checkboxcentralities"
                        ),
                        column(width = 2, numericInput("nColsCentralitiesGroup", "Columns", 3, min = 1, max = 9, step = 1))
                      ), width = 12)),
                      div(
                        class = "box-header-with-export", style = "margin-bottom: 10px;",
                        span("Export:", style = "color: #666;"), plotExportButtons("groupCentralitiesPlot")
                      ),
                      div(jqui_resizable(plotOutput("groupCentralitiesPlot", width = "900px", height = "600px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")
                      ), align = "center")
                    )
                  )
                ))
              )
            ),
            conditionalPanel(
              "input.inputType != 'long' & input.inputType != 'sample'",
              box(span(icon("circle-info", class = "text-danger"), "Comparison operations are only supported in long data"), width = 7)
            )
          ),

          # Group Networks Tab
          tabItem(
            tabName = "group_networks",
            conditionalPanel(
              "(input.inputType == 'long') | (input.inputType == 'sample')",
              fluidRow(
                column(
                  width = 3,
                  fluidRow(
                    box(
                      title = "Group Network Settings", width = 12,
                      selectInput("groupNetSelect", "Grouping Variable:", choices = NULL),
                      fluidRow(
                        column(6, numericInput("groupNetNcol", "Columns:", value = 2, min = 1, max = 6)),
                        column(6, numericInput("groupNetNrow", "Rows:", value = 1, min = 1, max = 6))
                      ),
                      hr(),
                      sliderInput("groupNetCut", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                      sliderInput("groupNetMinimum", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                      sliderInput("groupNetEdgeLabel", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                      sliderInput("groupNetVsize", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                      sliderInput("groupNetNodeLabel", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                      selectInput("groupNetLayout", "Layout", choices = c("circle", "spring"), selected = "circle")
                    )
                  )
                ),
                column(
                  width = 9,
                  fluidRow(box(
                    width = 12,
                    div(
                      class = "box-header-with-export",
                      h3(class = "box-title", "Group Network Visualization"),
                      plotExportButtons("groupNetPlot")
                    ),
                    div(jqui_resizable(plotOutput("groupNetPlot", width = "900px", height = "600px"),
                      options = list(ghost = TRUE, helper = "resizable-helper")
                    ), align = "center")
                  ))
                )
              )
            ),
            conditionalPanel(
              "input.inputType == 'sequence' || input.inputType == 'matrix'",
              box(span(
                icon("circle-info", class = "text-danger"),
                "Group network plots require long data or sample data with grouping variables"
              ), width = 7)
            )
          ),

          # Bootstrap Tab
          tabItem(
            tabName = "bootstrap",
            conditionalPanel(
              "input.inputType != 'matrix'",
              fluidRow(
                column(width = 3, fluidRow(
                  box(
                    title = "Bootstrap", width = 12,
                    numericInput("iterBoot", "Iteration:", min = 0, max = 10000, value = 1000, step = 100),
                    numericInput("levelBoot", "Level:", min = 0, max = 1, value = 0.05, step = 0.01),
                    selectInput("methodBoot", "Method", choices = c("stability", "threshold"), selected = "stability"),
                    conditionalPanel(
                      "input.methodBoot == 'threshold'",
                      numericInput("thresBoot", "Threshold:", min = 0, max = 1, value = 0.1, step = 0.01)
                    ),
                    conditionalPanel(
                      "input.methodBoot == 'stability'",
                      h4("Consistency Range"),
                      numericInput("constLowerBoot", "Lower:", min = 0, max = 10, value = 0.75, step = 0.01),
                      numericInput("constUpperBoot", "Upper:", min = 0, max = 10, value = 1.25, step = 0.01)
                    ),
                    actionButton("bootstrapButton", "Bootstrap", class = "btn-primary")
                  ),
                  box(
                    title = "Settings", width = 12,
                    sliderInput("cutBoot", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                    sliderInput("minimumBoot", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                    sliderInput("edge.labelBoot", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                    sliderInput("vsizeBoot", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                    sliderInput("node.labelBoot", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                    selectInput("layoutBoot", "Layout", choices = c("circle", "spring"), selected = "circle")
                  )
                )),
                column(width = 9, fluidRow(
                  box(
                    width = 12,
                    div(
                      class = "box-header-with-export",
                      h3(class = "box-title", "Bootstrap"),
                      plotExportButtons("tnaPlotBoot")
                    ),
                    div(jqui_resizable(plotOutput("tnaPlotBoot", width = "600px", height = "600px"),
                      options = list(ghost = TRUE, helper = "resizable-helper")
                    ), align = "center")
                  )
                ))
              )
            ),
            conditionalPanel(
              "input.inputType == 'matrix'",
              box(span(icon("circle-info", class = "text-danger"), "Bootstrap requires full data (not matrix input)"), width = 7)
            )
          ),

          # Permutation Tab (Group TNA mode only)
          tabItem(
            tabName = "permutation",
            conditionalPanel(
              "input.inputType != 'matrix'",
              fluidRow(
                column(width = 3, fluidRow(
                  box(
                    title = "Permutation", width = 12,
                    numericInput("iterPerm", "Iterations:", min = 100, max = 10000, value = 1000, step = 100),
                    numericInput("levelPerm", "Level:", min = 0, max = 1, value = 0.05, step = 0.01),
                    checkboxInput("pairedPerm", "Paired", value = FALSE),
                    actionButton("permutationButton", "Run Permutation", class = "btn-primary")
                  )
                )),
                column(width = 9, fluidRow(
                  box(
                    width = 12,
                    div(
                      class = "box-header-with-export",
                      h3(class = "box-title", "Permutation"),
                      plotExportButtons("permutationPlot")
                    ),
                    div(jqui_resizable(plotOutput("permutationPlot", width = "900px", height = "600px"),
                      options = list(ghost = TRUE, helper = "resizable-helper")
                    ), align = "center")
                  )
                ))
              )
            ),
            conditionalPanel(
              "input.inputType == 'matrix'",
              box(span(icon("circle-info", class = "text-danger"), "Permutation requires full data (not matrix input)"), width = 7)
            )
          ),

          # =====================================================================
          # GROUP MODE - Standalone Tab with Input Data and All Analyses
          # =====================================================================
          tabItem(
            tabName = "group_mode",
            # Data Input Section (similar to Input Data tab)
            fluidRow(
              column(
                width = 3,
                fluidRow(
                  box(
                    title = "Group TNA - Data Input", width = 12, status = "primary", solidHeader = TRUE,
                    radioButtons("gm_inputType", "Input Type:",
                      selected = character(0),
                      choices = c(
                        "Use Current Data" = "current", "Sample data" = "sample",
                        "Sequence Data" = "sequence", "Long Data" = "long"
                      )
                    ),
                    conditionalPanel(
                      "input.gm_inputType == 'sequence'",
                      fileInput("gm_fileInput", "Upload data file (sequence or wide data)")
                    ),
                    conditionalPanel(
                      "input.gm_inputType == 'long'",
                      fileInput("gm_longInput", "Upload long data"),
                      selectInput("gm_longAction", "Action:", choices = NULL, selectize = FALSE),
                      selectInput("gm_longActor", "Actor:", choices = NULL, selectize = FALSE),
                      selectInput("gm_longTime", "Time:", choices = NULL, selectize = FALSE),
                      selectInput("gm_longOrder", "Order:", choices = NULL, selectize = FALSE),
                      numericInput("gm_longThreshold", "Threshold:", min = 0, value = 900, step = 1),
                      textInput("gm_longDate", "Date format:", placeholder = "Not mandatory")
                    ),
                    hr(),
                    selectInput("gm_groupVar", "Grouping Variable:", choices = NULL),
                    selectInput("gm_type", "Analysis Type:", choices = c("relative", "frequency", "co-occurrence")),
                    fluidRow(
                      column(6, numericInput("gm_ncol", "Columns:", value = 2, min = 1, max = 6)),
                      column(6, numericInput("gm_nrow", "Rows:", value = 1, min = 1, max = 6))
                    ),
                    actionButton("gm_analyze", "Analyze Groups", class = "btn-primary")
                  )
                )
              ),
              column(
                width = 9,
                fluidRow(
                  conditionalPanel(
                    "!(input.gm_inputType)",
                    fluidRow(box(
                      width = 12, title = "Welcome to Group TNA!",
                      fluidRow(column(12, p("Select the format of your data on the left panel or use our example data."))),
                      fluidRow(column(12, p("Group TNA allows you to analyze data by groups, showing results for each group side by side."))),
                      fluidRow(
                        column(
                          6, span("Sample Data", class = "datatype"),
                          p("Pre-loaded example data with grouping variables for quick testing.")
                        ),
                        column(
                          6, span("Long Data (Recommended)", class = "datatype"),
                          p("Long-format data with grouping columns for comparison across groups.")
                        )
                      )
                    ))
                  ),
                  conditionalPanel(
                    "input.gm_inputType",
                    box(
                      title = "Data Preview", width = 12,
                      DTOutput("gm_dataPreview"),
                      conditionalPanel(
                        "input.gm_inputType != 'sample' & !input.gm_dataPreview_state",
                        span(icon("circle-info", class = "text-info"), "No data selected yet")
                      ),
                      tags$br(), uiOutput("gm_tnaModel")
                    )
                  )
                )
              )
            ),
            # Sub-tabs for all analyses
            fluidRow(
              tabBox(
                width = 12, id = "gm_tabset",
                # Visualization Tab
                tabPanel("Visualization",
                  icon = icon("project-diagram"),
                  fluidRow(
                    column(
                      width = 3,
                      box(
                        title = "Settings", width = 12,
                        sliderInput("gm_vis_cut", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                        sliderInput("gm_vis_minimum", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                        sliderInput("gm_vis_edge.label", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                        sliderInput("gm_vis_vsize", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                        sliderInput("gm_vis_node.label", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                        selectInput("gm_vis_layout", "Layout", choices = c("circle", "spring"), selected = "circle")
                      )
                    ),
                    column(
                      width = 9,
                      box(
                        width = 12,
                        div(
                          class = "box-header-with-export",
                          h3(class = "box-title", "Group Network Visualization"),
                          plotExportButtons("gm_visPlot")
                        ),
                        div(jqui_resizable(plotOutput("gm_visPlot", width = "900px", height = "600px"),
                          options = list(ghost = TRUE, helper = "resizable-helper")
                        ), align = "center")
                      )
                    )
                  )
                ),
                # Sequences Tab
                tabPanel("Sequences",
                  icon = icon("stream"),
                  fluidRow(
                    column(
                      width = 3,
                      box(
                        title = "Sequence Plot Settings", width = 12,
                        selectInput("gm_seq_type", "Plot Type:",
                          choices = c("Sequence Index" = "index", "Distribution" = "distribution"),
                          selected = "index"
                        ),
                        conditionalPanel(
                          "input.gm_seq_type == 'distribution'",
                          selectInput("gm_seq_scale", "Scale:",
                            choices = c("Proportion" = "proportion", "Count" = "count"),
                            selected = "proportion"
                          ),
                          selectInput("gm_seq_geom", "Geometry:",
                            choices = c("Bar" = "bar", "Area" = "area"),
                            selected = "bar"
                          )
                        ),
                        checkboxInput("gm_seq_includeNA", "Include NA values", value = FALSE),
                        checkboxInput("gm_seq_showN", "Show sample size (n)", value = TRUE),
                        numericInput("gm_seq_tick", "X-axis tick interval:", value = 5, min = 1, max = 20),
                        textInput("gm_seq_title", "Plot title:", placeholder = "Optional title"),
                        textInput("gm_seq_xlab", "X-axis label:", value = "Time"),
                        textInput("gm_seq_ylab", "Y-axis label:", placeholder = "Auto")
                      )
                    ),
                    column(
                      width = 9,
                      box(
                        width = 12,
                        div(
                          class = "box-header-with-export",
                          h3(class = "box-title", "Group Sequence Visualization"),
                          plotExportButtons("gm_seqPlot")
                        ),
                        div(jqui_resizable(plotOutput("gm_seqPlot", width = "900px", height = "600px"),
                          options = list(ghost = TRUE, helper = "resizable-helper")
                        ), align = "center")
                      )
                    )
                  )
                ),
                # Frequencies Tab
                tabPanel("Frequencies",
                  icon = icon("chart-bar"),
                  fluidRow(
                    column(
                      width = 3,
                      box(
                        title = "Frequency Plot Settings", width = 12,
                        sliderInput("gm_freq_width", "Bar width:", min = 0.1, max = 1, value = 0.7, step = 0.1),
                        checkboxInput("gm_freq_showLabel", "Show frequency labels", value = TRUE),
                        sliderInput("gm_freq_hjust", "Label position:", min = 0, max = 2, value = 1.2, step = 0.1)
                      )
                    ),
                    column(
                      width = 9,
                      box(
                        width = 12,
                        div(
                          class = "box-header-with-export",
                          h3(class = "box-title", "Group State Frequencies"),
                          plotExportButtons("gm_freqPlot")
                        ),
                        div(jqui_resizable(plotOutput("gm_freqPlot", width = "900px", height = "600px"),
                          options = list(ghost = TRUE, helper = "resizable-helper")
                        ), align = "center")
                      )
                    )
                  )
                ),
                # Centralities Tab
                tabPanel("Centralities",
                  icon = icon("bullseye"),
                  fluidRow(
                    box(
                      width = 12,
                      fluidRow(
                        column(
                          width = 6,
                          selectInput("gm_cent_measures", "Centralities",
                            multiple = TRUE,
                            choices = c(
                              "OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                              "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"
                            ),
                            selected = c("OutStrength", "InStrength", "Closeness", "Betweenness")
                          )
                        ),
                        column(
                          width = 3,
                          tags$label("Properties"),
                          checkboxInput("gm_cent_loops", "Loops?", value = FALSE),
                          checkboxInput("gm_cent_normalize", "Normalize?", value = FALSE)
                        ),
                        column(
                          width = 3,
                          numericInput("gm_cent_plotNcol", "Plot Columns", 3, min = 1, max = 9, step = 1)
                        )
                      )
                    )
                  ),
                  fluidRow(
                    box(
                      width = 12,
                      div(
                        class = "box-header-with-export",
                        h3(class = "box-title", "Group Centrality Measures"),
                        plotExportButtons("gm_centPlot")
                      ),
                      div(jqui_resizable(plotOutput("gm_centPlot", width = "900px", height = "800px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")
                      ), align = "center")
                    )
                  )
                ),
                # Communities Tab
                tabPanel("Communities",
                  icon = icon("users"),
                  fluidRow(
                    column(
                      width = 3,
                      box(
                        title = "Community Detection Settings", width = 12,
                        selectInput("gm_comm_algorithm", "Choose Algorithm:", choices = "spinglass"),
                        numericInput("gm_comm_gamma", "Gamma:", value = 1, min = 0, max = 100)
                      ),
                      box(
                        title = "Plotting Settings", width = 12,
                        sliderInput("gm_comm_cut", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                        sliderInput("gm_comm_minimum", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                        sliderInput("gm_comm_edge.label", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                        sliderInput("gm_comm_vsize", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                        sliderInput("gm_comm_node.label", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                        selectInput("gm_comm_layout", "Layout", choices = c("circle", "spring"), selected = "circle")
                      )
                    ),
                    column(
                      width = 9,
                      box(
                        width = 12,
                        div(
                          class = "box-header-with-export",
                          h3(class = "box-title", "Group Community Detection Results"),
                          plotExportButtons("gm_commPlot")
                        ),
                        div(jqui_resizable(plotOutput("gm_commPlot", width = "900px", height = "600px"),
                          options = list(ghost = TRUE, helper = "resizable-helper")
                        ), align = "center")
                      )
                    )
                  )
                ),
                # Cliques Tab
                tabPanel("Cliques",
                  icon = icon("sitemap"),
                  fluidRow(
                    column(
                      width = 3,
                      box(
                        title = "Clique Settings", width = 12,
                        numericInput("gm_cliq_size", "Clique Size (n):", value = 3, min = 2, max = 10),
                        numericInput("gm_cliq_threshold", "Threshold:", value = 0, min = 0, max = 1, step = 0.05),
                        actionButton("gm_findCliques", "Find Cliques", class = "btn-primary")
                      ),
                      box(
                        title = "Plotting Settings", width = 12,
                        sliderInput("gm_cliq_cut", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                        sliderInput("gm_cliq_minimum", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                        sliderInput("gm_cliq_edge.label", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                        sliderInput("gm_cliq_vsize", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                        sliderInput("gm_cliq_node.label", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                        selectInput("gm_cliq_layout", "Layout", choices = c("circle", "spring"), selected = "circle")
                      )
                    ),
                    column(
                      width = 9,
                      box(
                        width = 12,
                        div(
                          class = "box-header-with-export",
                          h3(class = "box-title", "Group Cliques Found"),
                          plotExportButtons("gm_cliqPlot")
                        ),
                        div(jqui_resizable(plotOutput("gm_cliqPlot", width = "900px", height = "600px"),
                          options = list(ghost = TRUE, helper = "resizable-helper")
                        ), align = "center")
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    )
  }

  # --------------------------------------------------------------------------
  # Logout Handler
  # --------------------------------------------------------------------------

  observeEvent(input$logout_btn, {
    showModal(modalDialog(
      title = "Sign Out",
      p("Are you sure you want to sign out?"),
      p(class = "text-muted", "Your analyses are safely stored in your Google Drive."),
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirm_logout", "Sign Out", class = "btn-danger")
      )
    ))
  })

  observeEvent(input$confirm_logout, {
    # Clear browser storage first
    session$sendCustomMessage("clearAuth", list())

    auth$logged_in <- FALSE
    auth$user_email <- NULL
    auth$user_name <- NULL
    auth$user_picture <- NULL
    auth$access_token <- NULL
    folder_ids(NULL)
    tryCatch(googledrive::drive_deauth(), error = function(e) {})
    removeModal()
    session$reload()
  })

  # Open TNA folder in Google Drive
  observeEvent(input$menu_open_drive, {
    folders <- folder_ids()
    if (!is.null(folders) && !is.null(folders$root)) {
      # Open the TNA_App folder directly
      drive_url <- paste0("https://drive.google.com/drive/folders/", folders$root)
      runjs(sprintf('window.open("%s", "_blank");', drive_url))
    } else {
      # Fallback to generic Drive
      runjs('window.open("https://drive.google.com/drive/my-drive", "_blank");')
      showNotification("TNA folder not found. Opening My Drive.", type = "warning")
    }
  })

  # --------------------------------------------------------------------------
  # Analysis Reactive Values (Original TNA Logic)
  # --------------------------------------------------------------------------

  rv <- reactiveValues(
    original = NULL,
    data = NULL,
    tna_result = NULL,
    centrality_result = NULL,
    cliques_result = NULL,
    clique_plots = list(),
    community_result = NULL,
    bootstrap_result = NULL,
    # Group Mode specific results
    gm_data = NULL, # Data for Group Mode
    gm_group_tna = NULL, # Group TNA model
    gm_cliques = NULL, # Cliques per group
    gm_bootstrap = NULL, # Bootstrap results per group
    permutation_result = NULL # Permutation test results
  )

  mar <- DEFAULT_MAR

  # --------------------------------------------------------------------------
  # Mode Tab Switching (TNA vs Group TNA)
  # --------------------------------------------------------------------------

  # Track current mode
  current_mode <- reactiveVal("tna")

  # Click on TNA tab
  observeEvent(input$mode_tna, {
    current_mode("tna")
    # Update tab styles and hide group selector
    shinyjs::runjs("$('#mode_tna').css('color', '#3c8dbc'); $('#mode_group_tna').css('color', '#999');")
    shinyjs::hide("group_input_container")
    # Show menu items for regular TNA
    shinyjs::runjs("$('a[data-value=\"results\"]').parent().show();")
    shinyjs::runjs("$('a[data-value=\"associations\"]').parent().show();")
    shinyjs::runjs("$('a[data-value=\"group_networks\"]').parent().show();")
    shinyjs::runjs("$('a[data-value=\"comparison\"]').parent().show();")
    shinyjs::runjs("$('a[data-value=\"cliques\"]').parent().show();")
    shinyjs::runjs("$('a[data-value=\"edgebet\"]').parent().show();")
    # Hide permutation menu (Group TNA only)
    shinyjs::runjs("$('a[data-value=\"permutation\"]').hide();")
    shinyjs::runjs("$('a[data-value=\"permutation\"]').parent().hide();")
  })

  # Click on Group TNA tab
  observeEvent(input$mode_group_tna, {
    current_mode("group_tna")
    # Update tab styles and show group selector
    shinyjs::runjs("$('#mode_tna').css('color', '#999'); $('#mode_group_tna').css('color', '#3c8dbc');")
    shinyjs::show("group_input_container")
    # Hide menu items not applicable for Group TNA
    shinyjs::runjs("$('a[data-value=\"results\"]').parent().hide();")
    shinyjs::runjs("$('a[data-value=\"associations\"]').parent().hide();")
    shinyjs::runjs("$('a[data-value=\"group_networks\"]').parent().hide();")
    shinyjs::runjs("$('a[data-value=\"comparison\"]').parent().hide();")
    shinyjs::runjs("$('a[data-value=\"cliques\"]').parent().hide();")
    # Show permutation menu (Group TNA only)
    shinyjs::runjs("$('a[data-value=\"permutation\"]').show();")
    shinyjs::runjs("$('a[data-value=\"permutation\"]').parent().show();")
    # Group selector is populated when data is uploaded (in dataPreview render)
  })

  # --------------------------------------------------------------------------
  # Save/Load Handlers
  # --------------------------------------------------------------------------

  # Save button
  observeEvent(input$btn_save, {
    if (is.null(rv$tna_result)) {
      showNotification("No analysis to save. Please run an analysis first.", type = "warning")
      return()
    }
    showModal(modalDialog(
      title = tagList(icon("cloud-arrow-up"), " Save Analysis to Google Drive"),
      size = "m", easyClose = TRUE,
      div(
        textInput("save_name", "Analysis Name", placeholder = "Enter a name for your analysis"),
        textAreaInput("save_description", "Description (optional)", placeholder = "Add notes...", rows = 3),
        checkboxInput("include_data", "Include original dataset", value = TRUE),
        checkboxInput("include_results", "Include all computed results", value = TRUE),
        div(
          class = "save-info", icon("info-circle"),
          span("Your analysis will be saved to your Google Drive in the TNA_App/analyses folder.")
        )
      ),
      footer = tagList(
        modalButton("Cancel"),
        actionButton("do_save", "Save to Drive", class = "btn-primary", icon = icon("cloud-arrow-up"))
      )
    ))
  })

  # Execute save
  observeEvent(input$do_save, {
    name <- trimws(input$save_name)
    if (name == "") {
      showNotification("Please enter a name", type = "error")
      return()
    }

    showNotification("Saving to Google Drive...", id = "save_prog", duration = NULL)

    analysis_data <- list(
      tna_result = rv$tna_result,
      centrality_result = if (input$include_results) rv$centrality_result else NULL,
      community_result = if (input$include_results) rv$community_result else NULL,
      cliques_result = if (input$include_results) rv$cliques_result else NULL,
      bootstrap_result = if (input$include_results) rv$bootstrap_result else NULL,
      original = if (input$include_data) rv$original else NULL,
      data = rv$data,
      settings = list(
        type = input$type, cut = input$cut, minimum = input$minimum,
        layout = input$layout, vsize = input$vsize
      )
    )

    result <- save_analysis_to_drive(folder_ids(), analysis_data, name, input$save_description)
    removeNotification("save_prog")

    if (result$success) {
      showNotification(paste("Saved:", result$name), type = "message", duration = 3)
      removeModal()
    } else {
      showNotification(paste("Failed:", result$error), type = "error", duration = 5)
    }
  })

  # Load button
  observeEvent(input$btn_load, {
    showModal(modalDialog(
      title = tagList(icon("folder-open"), " Load Analysis from Google Drive"),
      size = "l", easyClose = TRUE,
      div(
        DTOutput("load_analyses_table"),
        uiOutput("load_selected_info")
      ),
      footer = tagList(
        actionButton("do_delete_analysis", "Delete", class = "btn-danger", icon = icon("trash")),
        modalButton("Cancel"),
        actionButton("do_load", "Load Selected", class = "btn-primary", icon = icon("folder-open"))
      )
    ))
  })

  # Also handle from user menu
  observeEvent(input$menu_my_analyses, {
    showModal(modalDialog(
      title = tagList(icon("folder-open"), " My Analyses"),
      size = "l", easyClose = TRUE,
      div(DTOutput("load_analyses_table"), uiOutput("load_selected_info")),
      footer = tagList(
        actionButton("do_delete_analysis", "Delete", class = "btn-danger"),
        modalButton("Cancel"),
        actionButton("do_load", "Load Selected", class = "btn-primary")
      )
    ))
  })

  # Analyses list for loading
  analyses_list <- reactive({
    req(folder_ids())
    list_analyses_from_drive(folder_ids())
  })

  output$load_analyses_table <- renderDT({
    df <- analyses_list()
    if (nrow(df) == 0) {
      return(datatable(data.frame(Message = "No saved analyses found"), options = list(dom = "t"), rownames = FALSE))
    }
    display_df <- data.frame(
      Name = df$name,
      Modified = sapply(df$modified, format_date_display),
      Size = sapply(df$size, format_file_size),
      check.names = FALSE
    )
    datatable(display_df, selection = "single", options = list(pageLength = 5, dom = "tp"), rownames = FALSE)
  })

  output$load_selected_info <- renderUI({
    sel <- input$load_analyses_table_rows_selected
    df <- analyses_list()
    if (length(sel) == 0 || nrow(df) == 0) {
      return(div(class = "text-muted", "Select an analysis"))
    }
    row <- df[sel, ]
    div(
      class = "analysis-preview",
      h5(row$name),
      p(
        tags$strong("File: "), row$filename, tags$br(),
        tags$strong("Modified: "), format_date_display(row$modified)
      )
    )
  })

  # Execute load
  observeEvent(input$do_load, {
    sel <- input$load_analyses_table_rows_selected
    df <- analyses_list()
    if (length(sel) == 0 || nrow(df) == 0) {
      showNotification("Please select an analysis", type = "error")
      return()
    }

    showNotification("Loading from Google Drive...", id = "load_prog", duration = NULL)
    row <- df[sel, ]
    analysis <- load_analysis_from_drive(row$id)
    removeNotification("load_prog")

    if (!is.null(analysis)) {
      rv$tna_result <- analysis$tna_result
      rv$centrality_result <- analysis$centrality_result
      rv$community_result <- analysis$community_result
      rv$cliques_result <- analysis$cliques_result
      rv$bootstrap_result <- analysis$bootstrap_result
      rv$original <- analysis$original_data
      rv$data <- analysis$processed_data

      # Update input type for conditional panels
      if (!is.null(analysis$settings$type)) {
        updateSelectInput(session, "type", selected = analysis$settings$type)
      }

      showNotification(paste("Loaded:", analysis$meta$name), type = "message", duration = 3)
      removeModal()
    } else {
      showNotification("Failed to load analysis", type = "error")
    }
  })

  # Delete analysis
  observeEvent(input$do_delete_analysis, {
    sel <- input$load_analyses_table_rows_selected
    df <- analyses_list()
    if (length(sel) == 0 || nrow(df) == 0) {
      showNotification("Please select an analysis to delete", type = "error")
      return()
    }
    row <- df[sel, ]
    showModal(modalDialog(
      title = "Confirm Delete",
      p("Are you sure you want to delete '", row$name, "'?"),
      footer = tagList(
        modalButton("Cancel"),
        actionButton("confirm_delete_analysis", "Delete", class = "btn-danger")
      )
    ))
  })

  observeEvent(input$confirm_delete_analysis, {
    sel <- input$load_analyses_table_rows_selected
    df <- analyses_list()
    if (length(sel) > 0 && nrow(df) > 0) {
      row <- df[sel, ]
      if (delete_analysis_from_drive(row$id)) {
        showNotification("Analysis deleted", type = "message")
      } else {
        showNotification("Failed to delete", type = "error")
      }
    }
    removeModal()
  })

  # Export button
  observeEvent(input$btn_export, {
    if (is.null(rv$tna_result)) {
      showNotification("No analysis to export. Please run an analysis first.", type = "warning")
      return()
    }
    showModal(modalDialog(
      title = tagList(icon("file-export"), " Export Results"),
      size = "m", easyClose = TRUE,
      div(
        h4("What to Export"),
        checkboxGroupInput("export_items", NULL,
          choices = c(
            "Transition Matrix" = "matrix", "Centrality Measures" = "centrality",
            "Initial Probabilities" = "initial", "Summary Statistics" = "summary"
          ),
          selected = c("matrix")
        ),
        hr(),
        radioButtons("export_format", "Format", choices = c("CSV" = "csv"), selected = "csv", inline = TRUE),
        radioButtons("export_dest", "Destination",
          choices = c("Download" = "download", "Save to Google Drive" = "drive"), selected = "download"
        )
      ),
      footer = tagList(
        modalButton("Cancel"),
        downloadButton("do_export", "Export", class = "btn-primary")
      )
    ))
  })

  output$do_export <- downloadHandler(
    filename = function() {
      paste0("tna_export_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
    },
    content = function(file) {
      items <- input$export_items
      if ("matrix" %in% items && !is.null(rv$tna_result)) {
        write.csv(rv$tna_result$weights, file, row.names = TRUE)
      }
    }
  )

  # --------------------------------------------------------------------------
  # Original TNA Server Logic
  # --------------------------------------------------------------------------

  observeEvent(input$inputType, {
    rv$original <- NULL
  })

  # Data analysis
  observeEvent(input$analyze, {
    req(input$inputType)
    req(input$type)

    # Check that data is loaded before proceeding
    if (is.null(rv$original)) {
      showNotification("No data loaded. Please upload a file first.", type = "error")
      return()
    }

    if (input$inputType == "sequence") {
      rv$data <- rv$original
      tryCatch(
        {
          rv$tna_result <- build_model(rv$data, type = req(input$type))
        },
        error = function(e) {
          message("Sequence analysis error: ", e$message)
          showNotification(paste("Error:", e$message), type = "error", duration = 5)
        }
      )
    } else if (input$inputType == "long") {
      tryCatch(
        {
          whitelist <- c(".session_id", ".standardized_time", ".session_nr")

          # Build arguments dynamically - only include non-empty selections
          prep_args <- list(data = rv$original)

          if (!is.null(input$longAction) && input$longAction != "") {
            prep_args$action <- input$longAction
            whitelist <- c(whitelist, input$longAction)
          }
          if (!is.null(input$longActor) && input$longActor != "") {
            prep_args$actor <- input$longActor
            whitelist <- c(whitelist, input$longActor)
          }
          if (!is.null(input$longTime) && input$longTime != "") {
            prep_args$time <- input$longTime
            whitelist <- c(whitelist, input$longTime)
          }
          if (!is.null(input$longOrder) && input$longOrder != "") {
            prep_args$order <- input$longOrder
            whitelist <- c(whitelist, input$longOrder)
          }
          if (!is.null(input$longDate) && input$longDate != "") {
            prep_args$custom_format <- input$longDate
          }
          if (!is.null(input$longThreshold) && input$longThreshold != "") {
            prep_args$time_threshold <- input$longThreshold
          } else {
            prep_args$time_threshold <- Inf
          }

          rv$data <- do.call(prepare_data, prep_args)
          rv$tna_result <- build_model(rv$data, type = req(input$type))

          # Get grouping choices - filter out internal columns and columns with too many unique values
          meta <- rv$data$meta_data
          groupchoices <- names(meta)
          groupchoices <- groupchoices[sapply(groupchoices, \(x) !(x %in% whitelist))]
          # Filter columns with suitable number of unique values (2-50 for grouping)
          if (length(groupchoices) > 0) {
            groupchoices <- groupchoices[sapply(groupchoices, function(col) {
              n_unique <- length(unique(meta[[col]]))
              n_unique > 1 && n_unique <= 50
            })]
          }
          if (length(groupchoices) == 0) groupchoices <- NULL
          updateSelectInput(session, "compareSelect", choices = groupchoices)
        },
        error = function(e) {
          err_msg <- conditionMessage(e)
          if (is.null(err_msg) || err_msg == "") err_msg <- as.character(e)
          message("Long data analysis error: ", err_msg)
          showNotification(paste("Error:", err_msg), type = "error", duration = 5)
          return()
        }
      )
    } else if (input$inputType == "matrix") {
      tryCatch(
        {
          matrix_data <- as.matrix(rv$original)
          rv$data <- matrix_data
          rv$tna_result <- tna(matrix_data)
        },
        error = function(e) {
          message("Matrix analysis error: ", e$message)
          showNotification(paste("Error:", e$message), type = "error", duration = 5)
        }
      )
    } else if (input$inputType == "sample") {
      tryCatch(
        {
          rv$data <- structure(
            list(
              long_data = NULL, sequence_data = rv$original,
              meta_data = data.frame(Achiever = c(rep("High", 1000), rep("Low", 1000))),
              statistics = NULL
            ),
            class = "tna_data"
          )
          groupchoices <- names(rv$data$meta_data)
          updateSelectInput(session, "compareSelect", choices = groupchoices)
          rv$tna_result <- build_model(rv$data, type = req(input$type))
          rv$tna_result$data$Achiever <- c(rep("High", 1000), rep("Low", 1000))
        },
        error = function(e) {
          message("Sample data analysis error: ", e$message)
          showNotification(paste("Error:", e$message), type = "error", duration = 5)
        }
      )
    }

    # Only update sliders if analysis succeeded
    if (is.null(rv$tna_result)) {
      return()
    }

    # Update slider ranges based on analysis type
    if ((req(input$type) == "frequency") || (req(input$type) == "co-occurrence")) {
      max_val <- max(rv$tna_result$weights)
      updateSliderInput(session, "minimum", max = max_val)
      updateSliderInput(session, "minimumCom", max = max_val)
      updateSliderInput(session, "minimumClique", max = nrow(rv$tna_result$weights))
      updateSliderInput(session, "minimumEbet", max = nrow(rv$tna_result$weights))
      updateSliderInput(session, "minimumGroup", max = nrow(rv$tna_result$weights))
      updateSliderInput(session, "minimumBoot", max = nrow(rv$tna_result$weights))
      updateSliderInput(session, "cut", max = max_val)
      updateSliderInput(session, "cutCom", max = max_val)
      updateSliderInput(session, "cutClique", max = max_val)
      updateSliderInput(session, "cutEbet", max = nrow(rv$tna_result$weights))
      updateSliderInput(session, "cutGroup", max = nrow(rv$tna_result$weights))
      updateSliderInput(session, "cutBoot", max = nrow(rv$tna_result$weights))
    } else {
      updateSliderInput(session, "minimum", max = 1)
      updateSliderInput(session, "minimumCom", max = 1)
      updateSliderInput(session, "minimumClique", max = 1)
      updateSliderInput(session, "minimumEbet", max = 1)
      updateSliderInput(session, "minimumGroup", max = 1)
      updateSliderInput(session, "minimumBoot", max = 1)
      updateSliderInput(session, "cut", max = 1)
      updateSliderInput(session, "cutCom", max = 1)
      updateSliderInput(session, "cutClique", max = 1)
      updateSliderInput(session, "cutEbet", max = 1)
      updateSliderInput(session, "cutGroup", max = 1)
      updateSliderInput(session, "cutBoot", max = 1)
    }

    vsize <- 8 * exp(-1 * nrow(rv$tna_result$weights) / 80) + 1
    updateSliderInput(session, "vsize", value = vsize)
    updateSliderInput(session, "vsizeClique", value = 9)
    updateSliderInput(session, "vsizeCom", value = vsize)
    updateSliderInput(session, "vsizeEbet", value = vsize)
    updateSliderInput(session, "vsizeGroup", value = vsize)
    updateSliderInput(session, "vsizeBoot", value = vsize)

    # Create group model if in Group TNA mode
    if (current_mode() == "group_tna" && !is.null(input$gm_groupVar) && input$gm_groupVar != "") {
      tryCatch(
        {
          rv$gm_group_tna <- group_model(rv$data, type = input$type, group = input$gm_groupVar)
          showNotification(paste("Group TNA created with", length(rv$gm_group_tna), "groups"), type = "message")
        },
        error = function(e) {
          message("Group model error: ", e$message)
          showNotification(paste("Group model error:", e$message), type = "error")
          rv$gm_group_tna <- NULL
        }
      )
    } else {
      rv$gm_group_tna <- NULL
    }
  })

  # Data Preview
  output$dataPreview <- renderDT({
    if (is.null(input$inputType)) {
      return(NULL)
    }

    if (!is.null(input$longInput) && input$inputType == "long") {
      rv$original <- import(input$longInput$datapath)
      theoptions <- c(Empty = "", names(rv$original))
      updateSelectInput(session, "longAction", choices = theoptions)
      updateSelectInput(session, "longActor", choices = theoptions)
      updateSelectInput(session, "longOrder", choices = theoptions)
      updateSelectInput(session, "longTime", choices = theoptions)
      # Populate Group selector for Group TNA mode
      updateSelectInput(session, "gm_groupVar", choices = theoptions)
    } else if (!is.null(input$matrixInput) && input$inputType == "matrix") {
      rv$original <- import(input$matrixInput$datapath, row.names = 1)
    } else if (!is.null(input$fileInput) && input$inputType == "sequence") {
      rv$original <- import(input$fileInput$datapath)
      # Populate Group selector for Group TNA mode
      theoptions <- c(Empty = "", names(rv$original))
      updateSelectInput(session, "gm_groupVar", choices = theoptions)
    } else if (input$inputType == "sample") {
      rv$original <- group_regulation
      # Populate Group selector with sample data columns
      theoptions <- c(Empty = "", names(group_regulation))
      updateSelectInput(session, "gm_groupVar", choices = theoptions)
    }

    rv$tna_result <- NULL
    rv$centrality_result <- NULL
    rv$cliques_result <- NULL
    rv$clique_plots <- list()
    rv$community_result <- NULL
    rv$bootstrap_result <- NULL

    datatable(rv$original, options = list(scrollX = TRUE))
  })

  output$summary_model <- renderPrint({
    rv$tna_result
  })
  output$summary_boot_model <- renderPrint({
    rv$bootstrap_result
  })
  output$tnaModel <- renderUI({
    if (is.null(rv$tna_result)) NULL else verbatimTextOutput("summary_model")
  })

  # Transition Matrix
  output$transitionMatrix <- renderDT({
    req(rv$tna_result)
    datatable(round(rv$tna_result$weights, 3), options = list(pageLength = 10, scrollX = TRUE))
  })

  # Initial Probabilities
  output$initialProbs <- renderDT({
    req(rv$tna_result)
    inits <- rv$tna_result$inits
    if (!is.null(inits)) {
      init_probs <- data.frame(Probability = round(inits, 3))
      datatable(init_probs, options = list(pageLength = 10, scrollX = TRUE))
    }
  })

  # Summary Statistics
  output$summaryStats <- renderTable({
    req(rv$tna_result)
    summary(rv$tna_result)
  })

  # Centrality Measures
  output$centralityPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          if (current_mode() == "group_tna" && !is.null(rv$gm_group_tna)) {
            # Group TNA mode - centralities function handles groups automatically
            centrality_result <- centralities(rv$gm_group_tna,
              measures = input$centralitiesChoice,
              normalize = input$normalize, loops = input$loops
            )
            rv$centrality_result <- centrality_result
            plot(centrality_result, ncol = input$nColsCentralities)
          } else {
            centrality_result <- centralities(rv$tna_result,
              measures = input$centralitiesChoice,
              normalize = input$normalize, loops = input$loops
            )
            rv$centrality_result <- centrality_result
            plot(centrality_result, ncol = input$nColsCentralities)
          }
        },
        error = function(e) showNotification("Error plotting centralities", type = "error")
      )
    },
    res = 100
  )

  output$centralityPrint <- renderTable({
    req(rv$centrality_result)
    data.frame(rv$centrality_result)
  })

  # TNA Plot (supports both regular TNA and Group TNA modes)
  output$tnaPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          if (current_mode() == "group_tna" && !is.null(rv$gm_group_tna)) {
            # Group TNA mode - use pre-computed group model
            n_groups <- length(rv$gm_group_tna)
            par(mfrow = c(1, n_groups))
            group_names <- names(rv$gm_group_tna)
            for (i in seq_along(rv$gm_group_tna)) {
              plot(rv$gm_group_tna[[i]],
                title = group_names[i], cut = input$cut, minimum = input$minimum,
                label.cex = input$node.label, edge.label.cex = input$edge.label, vsize = input$vsize,
                layout = input$layout, mar = mar
              )
            }
          } else {
            # Regular TNA mode
            plot(rv$tna_result,
              cut = input$cut, minimum = input$minimum, label.cex = input$node.label,
              edge.label.cex = input$edge.label, vsize = input$vsize, layout = input$layout, mar = mar
            )
          }
        },
        error = function(e) showNotification("Error plotting TNA", type = "error")
      )
    },
    res = 600
  )

  # Sequence Plot
  output$seqPlot <- renderPlot(
    {
      req(rv$tna_result)
      req(rv$data)
      req(input$inputType != "matrix")
      tryCatch(
        {
          # Build arguments for plot_sequences
          # Use rv$data (tna_data object) for sequence plots, not rv$tna_result
          args <- list(
            x = rv$data,
            type = input$seqPlotType,
            include_na = input$seqIncludeNA,
            show_n = input$seqShowN,
            tick = input$seqTick,
            ncol = input$seqNcol,
            xlab = input$seqXlab
          )

          # Add distribution-specific arguments
          if (input$seqPlotType == "distribution") {
            args$scale <- input$seqScale
            args$geom <- input$seqGeom
          }

          # Add optional title
          if (!is.null(input$seqTitle) && input$seqTitle != "") {
            args$title <- input$seqTitle
          }

          # Add optional ylab
          if (!is.null(input$seqYlab) && input$seqYlab != "") {
            args$ylab <- input$seqYlab
          }

          # Add grouping - use Group TNA variable if in Group TNA mode, otherwise use seqGroup
          if (current_mode() == "group_tna" && !is.null(input$gm_groupVar) && input$gm_groupVar != "") {
            args$group <- input$gm_groupVar
          } else if (!is.null(input$seqGroup) && input$seqGroup != "" && input$seqGroup != "None") {
            args$group <- input$seqGroup
          }

          do.call(plot_sequences, args)
        },
        error = function(e) {
          message("Sequence plot error: ", e$message)
          showNotification(paste("Error plotting sequences:", e$message), type = "error")
        }
      )
    },
    res = 100
  )

  # Update sequence group choices when data changes
  observeEvent(rv$data, {
    if (!is.null(rv$data) && !is.null(rv$data$meta_data)) {
      choices <- c("None" = "", names(rv$data$meta_data))
      updateSelectInput(session, "seqGroup", choices = choices)
    } else {
      updateSelectInput(session, "seqGroup", choices = c("None" = ""))
    }
  })

  # Frequencies Plot
  output$freqPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          if (current_mode() == "group_tna" && !is.null(rv$gm_group_tna)) {
            # Group TNA mode - function handles groups automatically
            plot_frequencies(rv$gm_group_tna,
              width = input$freqWidth,
              hjust = input$freqHjust,
              show_label = input$freqShowLabel
            )
          } else {
            plot_frequencies(rv$tna_result,
              width = input$freqWidth,
              hjust = input$freqHjust,
              show_label = input$freqShowLabel
            )
          }
        },
        error = function(e) {
          message("Frequency plot error: ", e$message)
          showNotification(paste("Error plotting frequencies:", e$message), type = "error")
        }
      )
    },
    res = 100
  )

  # Associations Plot
  output$assocPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          plot_associations(rv$tna_result,
            cut = input$assocCut,
            minimum = input$assocMinimum,
            label.cex = input$assocNodeLabel,
            edge.label.cex = input$assocEdgeLabel,
            vsize = input$assocVsize,
            layout = input$assocLayout,
            mar = mar
          )
        },
        error = function(e) {
          message("Association plot error: ", e$message)
          showNotification(paste("Error plotting associations:", e$message), type = "error")
        }
      )
    },
    res = 600
  )

  # Edge Betweenness Plot
  output$edgeBetPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          if (current_mode() == "group_tna" && !is.null(rv$gm_group_tna)) {
            # Group TNA mode - same loop pattern as tnaPlot
            n_groups <- length(rv$gm_group_tna)
            par(mfrow = c(1, n_groups))
            group_names <- names(rv$gm_group_tna)
            for (i in seq_along(rv$gm_group_tna)) {
              ebet <- betweenness_network(rv$gm_group_tna[[i]])
              plot(ebet,
                title = group_names[i], cut = input$cutEbet, minimum = input$minimumEbet,
                label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
                vsize = input$vsizeEbet, layout = input$layoutEbet, mar = mar
              )
            }
          } else {
            plot(betweenness_network(rv$tna_result),
              cut = input$cutEbet, minimum = input$minimumEbet,
              label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
              vsize = input$vsizeEbet, layout = input$layoutEbet, mar = mar
            )
          }
        },
        error = function(e) showNotification("Error plotting edge betweenness", type = "error")
      )
    },
    res = 600
  )

  # Community Plot
  output$communityPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          if (current_mode() == "group_tna" && !is.null(rv$gm_group_tna)) {
            # Group TNA mode - same loop pattern as tnaPlot
            n_groups <- length(rv$gm_group_tna)
            par(mfrow = c(1, n_groups))
            group_names <- names(rv$gm_group_tna)
            for (i in seq_along(rv$gm_group_tna)) {
              comm <- tna::communities(rv$gm_group_tna[[i]], gamma = input$gamma)
              plot(comm,
                method = input$communityAlgorithm, title = group_names[i], cut = input$cutCom,
                minimum = input$minimumCom, label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
                vsize = input$vsizeCom, layout = input$layoutCom, mar = mar
              )
            }
          } else {
            rv$community_result <- tna::communities(rv$tna_result, gamma = input$gamma)
            algorithm_choices <- sapply(names(rv$community_result$counts), function(alg) {
              paste0(alg, " (", rv$community_result$counts[[alg]], " communities)")
            })
            choices <- names(algorithm_choices)
            names(choices) <- paste0(names(rv$community_result$counts), " (", rv$community_result$counts, ")")
            updateSelectInput(session, "communityAlgorithm", choices = choices, selected = input$communityAlgorithm)
            plot(rv$community_result,
              method = input$communityAlgorithm, mar = mar, cut = input$cutCom,
              minimum = input$minimumCom, label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
              vsize = input$vsizeCom, layout = input$layoutCom
            )
          }
        },
        error = function(e) showNotification("Error plotting communities", type = "error")
      )
    },
    res = 600
  )

  # Clique Finding
  observeEvent(input$findCliques, {
    req(rv$tna_result)
    req(input$cliqueSize)
    req(input$cliqueThreshold)

    if (current_mode() == "group_tna" && !is.null(rv$gm_group_tna)) {
      # Group TNA mode - function handles groups automatically
      rv$cliques_result <- tna::cliques(rv$gm_group_tna,
        size = input$cliqueSize,
        threshold = input$cliqueThreshold, n = 1000
      )
    } else {
      rv$cliques_result <- tna::cliques(rv$tna_result,
        size = input$cliqueSize,
        threshold = input$cliqueThreshold, n = 1000
      )
    }

    if (length(rv$cliques_result$inits) > 0) {
      choices <- seq_along(rv$cliques_result$inits)
      names(choices) <- lapply(rv$cliques_result$inits, \(x) names(x) |> paste(collapse = " - "))
      names(choices) <- paste0("Clique ", choices, ": ", names(choices))
      updateSelectInput(session, "cliqueSelect", choices = choices, selected = 1)
    } else {
      updateSelectInput(session, "cliqueSelect", selected = NULL, choices = NULL)
    }
  })

  output$cliquesPlot <- renderPlot(
    {
      req(rv$cliques_result)
      if (is.null(input$cliqueSelect) || input$cliqueSelect == "") {
        return(NULL)
      }
      tryCatch(
        {
          plot(rv$cliques_result,
            first = as.integer(input$cliqueSelect), n = 1, ask = FALSE,
            cut = input$cutClique, minimum = input$minimumClique, label.cex = input$node.labelClique,
            edge.label.cex = input$edge.labelClique, vsize = input$vsizeClique, layout = input$layoutClique, mar = mar
          )
        },
        error = function(e) showNotification("Error plotting cliques", type = "error")
      )
    },
    res = 600
  )

  # Comparison
  observeEvent(input$compareSelect, {
    if (is.null(rv$data$meta_data)) {
      return()
    }
    choices <- unique(data.frame(rv$data$meta_data)[, input$compareSelect])
    updateSelectInput(session, "group1",
      choices = choices,
      selected = if (!is.null(choices) && length(choices) > 0) choices[1] else rlang::missing_arg()
    )
    updateSelectInput(session, "group2",
      choices = choices,
      selected = if (!is.null(choices) && length(choices) > 1) choices[2] else rlang::missing_arg()
    )
  })

  output$comparisonPlot <- renderPlot(
    {
      req(rv$data)
      tryCatch(
        {
          group_tnad <- group_model(req(rv$data), type = req(input$type), group = req(input$compareSelect))
          if (input$compare_sig) {
            differentrows <- nrow(group_tnad[[req(input$group1)]]$data) != nrow(group_tnad[[req(input$group2)]]$data)
            permtest <- permutation_test(group_tnad[[req(input$group1)]], group_tnad[[req(input$group2)]],
              iter = input$iterPerm, paired = if (differentrows) FALSE else input$pairedPerm, level = input$levelPerm
            )
            if (differentrows && input$pairedPerm) {
              showNotification("Paired test cannot be applied - groups have different sizes", type = "warning")
            }
            plot(permtest,
              cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
              edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup, mar = mar
            )
          } else {
            plot_compare(group_tnad[[req(input$group1)]], group_tnad[[req(input$group2)]],
              cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
              edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup,
              posCol = "darkblue", negCol = "red", mar = mar
            )
          }
        },
        error = function(e) showNotification("Error in comparison", type = "error")
      )
    },
    res = 600
  )

  output$mosaicPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          group_tnad <- group_model(req(rv$data), type = req(input$type), group = req(input$compareSelect))
          plot_mosaic(group_tnad)
        },
        error = function(e) showNotification("Error plotting mosaic", type = "error")
      )
    },
    res = 100
  )

  output$groupCentralitiesPlot <- renderPlot(
    {
      req(rv$tna_result)
      tryCatch(
        {
          group_tnad <- group_model(req(rv$data), type = req(input$type), group = req(input$compareSelect))
          plot(centralities(group_tnad,
            measures = input$centralitiesChoiceGroup,
            normalize = input$normalizeGroup, loops = input$loopsGroup
          ), ncol = input$nColsCentralitiesGroup)
        },
        error = function(e) showNotification("Error plotting group centralities", type = "error")
      )
    },
    res = 100
  )

  # Group Networks - update grouping variable choices when data changes
  observeEvent(rv$data, {
    if (!is.null(rv$data) && !is.null(rv$data$meta_data)) {
      meta <- rv$data$meta_data
      choices <- names(meta)
      # Filter out internal columns
      choices <- choices[!grepl("^\\.session|^\\.standardized|^\\.session_nr", choices)]
      # Filter out columns with too many unique values (likely IDs, not categorical)
      # Keep only columns with <= 50 unique values for meaningful grouping
      if (length(choices) > 0) {
        choices <- choices[sapply(choices, function(col) {
          n_unique <- length(unique(meta[[col]]))
          n_unique > 1 && n_unique <= 50
        })]
      }
      if (length(choices) > 0) {
        updateSelectInput(session, "groupNetSelect", choices = choices)
      } else {
        updateSelectInput(session, "groupNetSelect", choices = c("No suitable grouping variables" = ""))
      }
    } else {
      updateSelectInput(session, "groupNetSelect", choices = NULL)
    }
  })

  # Update group choices when grouping variable changes
  observeEvent(input$groupNetSelect, {
    req(rv$data)
    req(input$groupNetSelect)
    if (!is.null(rv$data$meta_data) && input$groupNetSelect %in% names(rv$data$meta_data)) {
      groups <- unique(rv$data$meta_data[[input$groupNetSelect]])
      updateSelectInput(session, "groupNetWhich", choices = groups, selected = groups)
    }
  })

  # Group Networks Plot
  output$groupNetPlot <- renderPlot(
    {
      req(rv$tna_result)
      req(rv$data)
      req(input$groupNetSelect)
      req(input$groupNetSelect != "")
      tryCatch(
        {
          group_tnad <- group_model(rv$data, type = input$type, group = input$groupNetSelect)
          n_groups <- length(group_tnad)

          # Set up grid layout
          ncol <- input$groupNetNcol %||% 2
          nrow <- input$groupNetNrow %||% ceiling(n_groups / ncol)
          par(mfrow = c(nrow, ncol))

          # Plot each group
          group_names <- names(group_tnad)
          for (i in seq_along(group_tnad)) {
            plot(group_tnad[[i]],
              title = group_names[i],
              cut = input$groupNetCut,
              minimum = input$groupNetMinimum,
              label.cex = input$groupNetNodeLabel,
              edge.label.cex = input$groupNetEdgeLabel,
              vsize = input$groupNetVsize,
              layout = input$groupNetLayout,
              mar = mar
            )
          }
        },
        error = function(e) {
          message("Group network plot error: ", e$message)
          showNotification(paste("Error plotting group networks:", e$message), type = "error")
        }
      )
    },
    res = 150
  )

  # ==========================================================================
  # GROUP MODE - Server Logic
  # ==========================================================================

  # Group Mode original data storage
  gm_original <- reactiveVal(NULL)

  # Reset Group Mode data when input type changes
  observeEvent(input$gm_inputType, {
    gm_original(NULL)
    rv$gm_data <- NULL
    rv$gm_group_tna <- NULL
    rv$gm_cliques <- NULL
  })

  # Group Mode - Data Preview
  output$gm_dataPreview <- renderDT({
    if (is.null(input$gm_inputType)) {
      return(NULL)
    }

    if (!is.null(input$gm_longInput) && input$gm_inputType == "long") {
      gm_original(import(input$gm_longInput$datapath))
      theoptions <- c(Empty = "", names(gm_original()))
      updateSelectInput(session, "gm_longAction", choices = theoptions)
      updateSelectInput(session, "gm_longActor", choices = theoptions)
      updateSelectInput(session, "gm_longOrder", choices = theoptions)
      updateSelectInput(session, "gm_longTime", choices = theoptions)
      # Update grouping variable choices with all columns from long data
      updateSelectInput(session, "gm_groupVar", choices = names(gm_original()))
    } else if (!is.null(input$gm_fileInput) && input$gm_inputType == "sequence") {
      gm_original(import(input$gm_fileInput$datapath))
      # Update grouping variable choices with all columns from sequence data
      updateSelectInput(session, "gm_groupVar", choices = names(gm_original()))
    } else if (input$gm_inputType == "sample") {
      gm_original(group_regulation)
      # Sample data has "Achiever" as grouping variable
      updateSelectInput(session, "gm_groupVar", choices = c("Achiever"))
    } else if (input$gm_inputType == "current") {
      # Use data from regular TNA mode
      if (is.null(rv$data)) {
        showNotification("No data loaded in TNA mode. Please load data first.", type = "error")
        return(NULL)
      }
      gm_original(rv$data)
      # Get grouping choices from metadata
      if (!is.null(rv$data$meta_data)) {
        updateSelectInput(session, "gm_groupVar", choices = names(rv$data$meta_data))
      }
    }

    datatable(gm_original(), options = list(scrollX = TRUE))
  })

  output$gm_summary_model <- renderPrint({
    rv$gm_group_tna
  })
  output$gm_tnaModel <- renderUI({
    if (is.null(rv$gm_group_tna)) NULL else verbatimTextOutput("gm_summary_model")
  })

  # Observer for Analyze Groups button
  observeEvent(input$gm_analyze, {
    req(input$gm_inputType)

    # Check that data is loaded before proceeding
    if (is.null(gm_original())) {
      showNotification("No data loaded. Please upload a file or select Sample data first.", type = "error")
      return()
    }

    tryCatch(
      {
        whitelist <- c(".session_id", ".standardized_time", ".session_nr")

        if (input$gm_inputType == "sequence") {
          rv$gm_data <- gm_original()
          # Sequence data doesn't have metadata for grouping - need to add it manually or error
          showNotification("Note: Sequence data may not have grouping variables. Consider using Long Data format.", type = "warning", duration = 5)
        } else if (input$gm_inputType == "long") {
          # Build arguments dynamically
          prep_args <- list(data = gm_original())

          if (!is.null(input$gm_longAction) && input$gm_longAction != "") {
            prep_args$action <- input$gm_longAction
            whitelist <- c(whitelist, input$gm_longAction)
          }
          if (!is.null(input$gm_longActor) && input$gm_longActor != "") {
            prep_args$actor <- input$gm_longActor
            whitelist <- c(whitelist, input$gm_longActor)
          }
          if (!is.null(input$gm_longTime) && input$gm_longTime != "") {
            prep_args$time <- input$gm_longTime
            whitelist <- c(whitelist, input$gm_longTime)
          }
          if (!is.null(input$gm_longOrder) && input$gm_longOrder != "") {
            prep_args$order <- input$gm_longOrder
            whitelist <- c(whitelist, input$gm_longOrder)
          }
          if (!is.null(input$gm_longDate) && input$gm_longDate != "") {
            prep_args$custom_format <- input$gm_longDate
          }
          if (!is.null(input$gm_longThreshold) && input$gm_longThreshold != "") {
            prep_args$time_threshold <- input$gm_longThreshold
          } else {
            prep_args$time_threshold <- Inf
          }

          rv$gm_data <- do.call(prepare_data, prep_args)

          # Get grouping choices - filter out only internal columns, show all others
          meta <- rv$gm_data$meta_data
          groupchoices <- names(meta)
          groupchoices <- groupchoices[sapply(groupchoices, \(x) !(x %in% whitelist))]
          if (length(groupchoices) == 0) groupchoices <- NULL
          updateSelectInput(session, "gm_groupVar", choices = groupchoices)
        } else if (input$gm_inputType == "sample") {
          rv$gm_data <- structure(
            list(
              long_data = NULL, sequence_data = gm_original(),
              meta_data = data.frame(Achiever = c(rep("High", 1000), rep("Low", 1000))),
              statistics = NULL
            ),
            class = "tna_data"
          )
          # Don't update groupVar here - already set in observer
        } else if (input$gm_inputType == "current") {
          # Use data from regular TNA mode
          if (is.null(rv$data)) {
            showNotification("No data loaded in TNA mode. Please load data first.", type = "error")
            return()
          }
          rv$gm_data <- rv$data
        }

        # Create group model
        req(rv$gm_data)

        # Get grouping variable - use current selection or default for sample data
        gm_group <- input$gm_groupVar
        if (is.null(gm_group) || gm_group == "") {
          if (input$gm_inputType == "sample") {
            gm_group <- "Achiever"
          } else {
            showNotification("Please select a grouping variable", type = "error")
            return()
          }
        }

        message("Creating group model with group: ", gm_group)
        rv$gm_group_tna <- group_model(rv$gm_data, type = input$gm_type, group = gm_group)
        message("Group model created with ", length(rv$gm_group_tna), " groups")
        showNotification(paste("Group analysis ready with", length(rv$gm_group_tna), "groups"), type = "message", duration = 3)
      },
      error = function(e) {
        err_msg <- conditionMessage(e)
        if (is.null(err_msg) || err_msg == "") err_msg <- as.character(e)
        message("Group Mode analyze error: ", err_msg)
        showNotification(paste("Error:", err_msg), type = "error", duration = 5)
      }
    )
  })

  # Update grouping variable choices when input type changes
  observeEvent(input$gm_inputType,
    {
      if (!is.null(input$gm_inputType) && input$gm_inputType == "sample") {
        # Load sample data immediately
        gm_original(group_regulation)
        # Sample data has "Achiever" as grouping variable
        updateSelectInput(session, "gm_groupVar", choices = c("Achiever"), selected = "Achiever")
      } else if (!is.null(input$gm_inputType) && input$gm_inputType == "current") {
        # Use data from regular TNA mode immediately
        if (!is.null(rv$data) && !is.null(rv$data$meta_data)) {
          gm_original(rv$data)
          updateSelectInput(session, "gm_groupVar", choices = names(rv$data$meta_data))
        } else {
          showNotification("No data loaded in TNA mode. Please load data first.", type = "warning")
          updateSelectInput(session, "gm_groupVar", choices = NULL)
        }
      } else {
        # Clear grouping variable for other input types until data is loaded
        updateSelectInput(session, "gm_groupVar", choices = NULL)
      }
    },
    ignoreInit = TRUE
  )

  # Group Mode - Visualization Plot (create fresh group_model like Group Networks)
  output$gm_visPlot <- renderPlot(
    {
      req(rv$gm_data)
      req(input$gm_groupVar)
      req(input$gm_groupVar != "")

      # Create group model fresh (same as Group Networks)
      group_tnad <- group_model(rv$gm_data, type = input$gm_type, group = input$gm_groupVar)
      n_groups <- length(group_tnad)

      # Set up grid layout
      ncol <- input$gm_ncol %||% 2
      nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
      par(mfrow = c(nrow, ncol))

      # Plot each group
      group_names <- names(group_tnad)
      for (i in seq_along(group_tnad)) {
        plot(group_tnad[[i]],
          title = group_names[i],
          cut = input$gm_vis_cut,
          minimum = input$gm_vis_minimum,
          label.cex = input$`gm_vis_node.label`,
          edge.label.cex = input$`gm_vis_edge.label`,
          vsize = input$gm_vis_vsize,
          layout = input$gm_vis_layout,
          mar = mar
        )
      }
    },
    res = 150
  )

  # Group Mode - Sequences Plot
  output$gm_seqPlot <- renderPlot(
    {
      req(rv$gm_data)
      req(input$gm_groupVar)
      req(input$gm_groupVar != "")
      tryCatch(
        {
          # Calculate grid dimensions
          ncol_val <- input$gm_ncol %||% 2
          nrow_val <- input$gm_nrow %||% 2
          # Use plot_sequences with grouping
          args <- list(
            x = rv$gm_data,
            type = input$gm_seq_type,
            group = input$gm_groupVar,
            ncol = ncol_val,
            nrow = nrow_val,
            include_na = input$gm_seq_includeNA,
            show_n = input$gm_seq_showN,
            tick = input$gm_seq_tick,
            xlab = if (input$gm_seq_xlab != "") input$gm_seq_xlab else "Time"
          )
          if (input$gm_seq_title != "") args$title <- input$gm_seq_title
          if (input$gm_seq_ylab != "") args$ylab <- input$gm_seq_ylab
          if (input$gm_seq_type == "distribution") {
            args$scale <- input$gm_seq_scale
            args$geom <- input$gm_seq_geom
          }
          do.call(plot_sequences, args)
        },
        error = function(e) {
          message("Group Mode sequences error: ", e$message)
          showNotification(paste("Error:", e$message), type = "error")
        }
      )
    },
    res = 100
  )

  # Group Mode - Frequencies Plot
  output$gm_freqPlot <- renderPlot(
    {
      req(rv$gm_group_tna)
      tryCatch(
        {
          n_groups <- length(rv$gm_group_tna)
          ncol_val <- input$gm_ncol %||% 2
          nrow_val <- input$gm_nrow %||% ceiling(n_groups / ncol_val)
          plot_frequencies(rv$gm_group_tna,
            width = input$gm_freq_width,
            hjust = input$gm_freq_hjust,
            show_label = input$gm_freq_showLabel,
            ncol = ncol_val,
            nrow = nrow_val
          )
        },
        error = function(e) {
          message("Group Mode frequencies error: ", e$message)
          showNotification(paste("Error:", e$message), type = "error")
        }
      )
    },
    res = 100
  )

  # Group Mode - Centralities Plot
  output$gm_centPlot <- renderPlot(
    {
      req(rv$gm_group_tna)
      tryCatch(
        {
          cent_result <- centralities(rv$gm_group_tna,
            measures = input$gm_cent_measures,
            normalize = input$gm_cent_normalize,
            loops = input$gm_cent_loops
          )
          plot(cent_result, ncol = input$gm_cent_plotNcol)
        },
        error = function(e) {
          message("Group Mode centralities error: ", e$message)
          showNotification(paste("Error:", e$message), type = "error")
        }
      )
    },
    res = 100
  )

  # Group Mode - Communities Plot (same pattern as Group Networks)
  output$gm_commPlot <- renderPlot(
    {
      req(rv$gm_group_tna)
      n_groups <- length(rv$gm_group_tna)
      ncol <- input$gm_ncol %||% 2
      nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
      par(mfrow = c(nrow, ncol))
      group_names <- names(rv$gm_group_tna)
      for (i in seq_along(rv$gm_group_tna)) {
        comm <- tna::communities(rv$gm_group_tna[[i]], gamma = input$gm_comm_gamma)
        plot(comm,
          title = group_names[i],
          method = input$gm_comm_algorithm,
          mar = mar,
          cut = input$gm_comm_cut,
          minimum = input$gm_comm_minimum,
          label.cex = input$`gm_comm_node.label`,
          edge.label.cex = input$`gm_comm_edge.label`,
          vsize = input$gm_comm_vsize,
          layout = input$gm_comm_layout
        )
      }
    },
    res = 150
  )

  # Group Mode - Find Cliques Button
  observeEvent(input$gm_findCliques, {
    req(rv$gm_group_tna)
    tryCatch(
      {
        rv$gm_cliques <- tna::cliques(rv$gm_group_tna,
          size = input$gm_cliq_size,
          threshold = input$gm_cliq_threshold,
          n = 1000
        )
        showNotification("Cliques found for all groups!", type = "message")
      },
      error = function(e) {
        message("Group Mode find cliques error: ", e$message)
        showNotification(paste("Error finding cliques:", e$message), type = "error")
      }
    )
  })

  # Group Mode - Cliques Plot (same pattern as Group Networks)
  output$gm_cliqPlot <- renderPlot(
    {
      req(rv$gm_cliques)
      n_groups <- length(rv$gm_group_tna)
      ncol <- input$gm_ncol %||% 2
      nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
      par(mfrow = c(nrow, ncol))
      group_names <- names(rv$gm_cliques)
      for (i in seq_along(rv$gm_cliques)) {
        plot(rv$gm_cliques[[i]],
          title = group_names[i],
          first = 1,
          n = 1,
          ask = FALSE,
          cut = input$gm_cliq_cut,
          minimum = input$gm_cliq_minimum,
          label.cex = input$`gm_cliq_node.label`,
          edge.label.cex = input$`gm_cliq_edge.label`,
          vsize = input$gm_cliq_vsize,
          layout = input$gm_cliq_layout,
          mar = mar
        )
      }
    },
    res = 150
  )

  # Bootstrap (works in both TNA and Group TNA modes)
  observeEvent(input$bootstrapButton, {
    # Determine mode and required data
    is_group_mode <- current_mode() == "group_tna"

    tryCatch(
      {
        if (is_group_mode) {
          # Validations for Group Mode
          if (is.null(rv$gm_group_tna)) {
            showNotification("Please run 'Analyze Groups' first.", type = "error")
            return()
          }

          # Group TNA mode - bootstrap the group model
          message("DEBUG: Starting Group TNA bootstrap")
          showNotification("Running group bootstrap...", id = "boot_prog", duration = NULL)

          message("DEBUG: Calling tna::bootstrap on gm_group_tna (class: ", class(rv$gm_group_tna), ")")
          rv$gm_bootstrap <- tna::bootstrap(rv$gm_group_tna,
            iter = input$iterBoot, level = input$levelBoot,
            method = input$methodBoot, threshold = input$thresBoot,
            consistency_range = sort(c(input$constLowerBoot, input$constUpperBoot))
          )

          message("DEBUG: Bootstrap finished. Result class: ", class(rv$gm_bootstrap))

          rv$bootstrap_result <- NULL
          removeNotification("boot_prog")
          showNotification("Group bootstrap completed!", type = "message")
        } else {
          # Validations for TNA Mode
          if (is.null(rv$tna_result)) {
            showNotification("Please load data and run 'Analyze' first.", type = "error")
            return()
          }

          # Regular TNA mode
          showNotification("Running bootstrap...", id = "boot_prog", duration = NULL)
          boot <- tna::bootstrap(rv$tna_result,
            iter = input$iterBoot, level = input$levelBoot,
            method = input$methodBoot, threshold = input$thresBoot,
            consistency_range = sort(c(input$constLowerBoot, input$constUpperBoot))
          )
          rv$bootstrap_result <- prune(rv$tna_result, method = "bootstrap", boot = boot)
          rv$gm_bootstrap <- NULL
          removeNotification("boot_prog")
          showNotification("Bootstrap completed!", type = "message")
        }
      },
      error = function(e) {
        removeNotification("boot_prog")
        showNotification(paste("Error in bootstrap:", e$message), type = "error")
      }
    )
  })

  output$tnaPlotBoot <- renderPlot(
    {
      tryCatch(
        {
          if (current_mode() == "group_tna" && !is.null(rv$gm_bootstrap)) {
            # Group TNA mode - plot bootstrap results (same logic as permutation)
            n <- length(rv$gm_bootstrap)
            if (n <= 4) {
              par(mfrow = c(2, 2))
            } else if (n <= 6) {
              par(mfrow = c(2, 3))
            } else {
              ncol <- ceiling(sqrt(n))
              nrow <- ceiling(n / ncol)
              par(mfrow = c(nrow, ncol))
            }
            plot(rv$gm_bootstrap)
          } else {
            req(rv$bootstrap_result)
            plot(rv$bootstrap_result,
              cut = input$cutBoot, minimum = input$minimumBoot,
              label.cex = input$node.labelBoot, edge.label.cex = input$edge.labelBoot,
              vsize = input$vsizeBoot, layout = input$layoutBoot, mar = mar
            )
          }
        },
        error = function(e) {
          message("DEBUG: Error plotting bootstrap: ", e$message)
          showNotification(paste("Error plotting:", e$message), type = "error")
        }
      )
    },
    res = 600
  )

  output$bootstrappedtnaModel <- renderUI({
    if (is.null(rv$bootstrap_result)) NULL else verbatimTextOutput("summary_boot_model")
  })

  # --------------------------------------------------------------------------
  # Permutation Test (Group TNA mode only)
  # --------------------------------------------------------------------------

  observeEvent(input$permutationButton, {
    if (is.null(rv$gm_group_tna)) {
      showNotification("Please run 'Analyze Groups' first.", type = "error")
      return()
    }

    tryCatch(
      {
        showNotification("Running permutation test...", id = "perm_prog", duration = NULL)
        rv$permutation_result <- tna::permutation_test(
          x = rv$gm_group_tna,
          iter = input$iterPerm,
          paired = input$pairedPerm,
          level = input$levelPerm
        )
        removeNotification("perm_prog")
        showNotification("Permutation test completed!", type = "message")
      },
      error = function(e) {
        removeNotification("perm_prog")
        showNotification(paste("Error in permutation test:", e$message), type = "error")
      }
    )
  })

  output$permutationPlot <- renderPlot(
    {
      req(rv$permutation_result)
      tryCatch(
        {
          n <- length(rv$permutation_result)
          if (n <= 4) {
            par(mfrow = c(2, 2))
          } else if (n <= 6) {
            par(mfrow = c(2, 3))
          } else {
            ncol <- ceiling(sqrt(n))
            nrow <- ceiling(n / ncol)
            par(mfrow = c(nrow, ncol))
          }
          plot(rv$permutation_result)
        },
        error = function(e) {
          showNotification(paste("Error plotting permutation:", e$message), type = "error")
        }
      )
    },
    res = 600
  )

  # --------------------------------------------------------------------------
  # Export Download Handlers
  # --------------------------------------------------------------------------

  # --- Table Exports ---

  # Summary Stats
  output$summaryStats_csv <- tableDownloadCSV(
    function() {
      if (!is.null(rv$tna_result)) as.data.frame(summary(rv$tna_result)) else NULL
    },
    "summary_stats"
  )
  output$summaryStats_xlsx <- tableDownloadXLSX(
    function() {
      if (!is.null(rv$tna_result)) as.data.frame(summary(rv$tna_result)) else NULL
    },
    "summary_stats"
  )

  # Initial Probabilities
  output$initialProbs_csv <- tableDownloadCSV(
    function() {
      if (!is.null(rv$tna_result) && !is.null(rv$tna_result$inits)) {
        data.frame(State = names(rv$tna_result$inits), Probability = round(rv$tna_result$inits, 3))
      } else {
        NULL
      }
    },
    "initial_probs"
  )
  output$initialProbs_xlsx <- tableDownloadXLSX(
    function() {
      if (!is.null(rv$tna_result) && !is.null(rv$tna_result$inits)) {
        data.frame(State = names(rv$tna_result$inits), Probability = round(rv$tna_result$inits, 3))
      } else {
        NULL
      }
    },
    "initial_probs"
  )

  # Transition Matrix
  output$transitionMatrix_csv <- tableDownloadCSV(
    function() {
      if (!is.null(rv$tna_result)) round(rv$tna_result$weights, 3) else NULL
    },
    "transition_matrix"
  )
  output$transitionMatrix_xlsx <- tableDownloadXLSX(
    function() {
      if (!is.null(rv$tna_result)) round(rv$tna_result$weights, 3) else NULL
    },
    "transition_matrix"
  )

  # Centrality Measures
  output$centralityPrint_csv <- tableDownloadCSV(
    function() {
      rv$centrality_result
    },
    "centrality_measures"
  )
  output$centralityPrint_xlsx <- tableDownloadXLSX(
    function() {
      rv$centrality_result
    },
    "centrality_measures"
  )

  # --- Plot Exports ---

  # TNA Plot
  output$tnaPlot_png <- plotDownloadPNG(function() {
    req(rv$tna_result)
    plot(rv$tna_result,
      cut = input$cut, minimum = input$minimum,
      label.cex = input$node.label, edge.label.cex = input$edge.label,
      vsize = input$vsize, layout = input$layout, mar = DEFAULT_MAR
    )
  }, "tna_network", 1200, 1000)

  output$tnaPlot_pdf <- plotDownloadPDF(function() {
    req(rv$tna_result)
    plot(rv$tna_result,
      cut = input$cut, minimum = input$minimum,
      label.cex = input$node.label, edge.label.cex = input$edge.label,
      vsize = input$vsize, layout = input$layout, mar = DEFAULT_MAR
    )
  }, "tna_network", 10, 8)

  # Sequence Plot
  output$seqPlot_png <- plotDownloadPNG(function() {
    req(rv$data)
    args <- list(
      x = rv$data, type = input$seqPlotType, include_na = input$seqIncludeNA,
      show_n = input$seqShowN, tick = input$seqTick, ncol = input$seqNcol, xlab = input$seqXlab
    )
    if (input$seqPlotType == "distribution") {
      args$scale <- input$seqScale
      args$geom <- input$seqGeom
    }
    if (!is.null(input$seqTitle) && input$seqTitle != "") args$title <- input$seqTitle
    if (!is.null(input$seqYlab) && input$seqYlab != "") args$ylab <- input$seqYlab
    if (!is.null(input$seqGroup) && input$seqGroup != "" && input$seqGroup != "None") args$group <- input$seqGroup
    do.call(plot_sequences, args)
  }, "sequence_plot", 1600, 1200)

  output$seqPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data)
    args <- list(
      x = rv$data, type = input$seqPlotType, include_na = input$seqIncludeNA,
      show_n = input$seqShowN, tick = input$seqTick, ncol = input$seqNcol, xlab = input$seqXlab
    )
    if (input$seqPlotType == "distribution") {
      args$scale <- input$seqScale
      args$geom <- input$seqGeom
    }
    if (!is.null(input$seqTitle) && input$seqTitle != "") args$title <- input$seqTitle
    if (!is.null(input$seqYlab) && input$seqYlab != "") args$ylab <- input$seqYlab
    if (!is.null(input$seqGroup) && input$seqGroup != "" && input$seqGroup != "None") args$group <- input$seqGroup
    do.call(plot_sequences, args)
  }, "sequence_plot", 12, 10)

  # Frequencies Plot
  output$freqPlot_png <- plotDownloadPNG(function() {
    req(rv$tna_result)
    plot_frequencies(rv$tna_result, width = input$freqWidth, hjust = input$freqHjust, show_label = input$freqShowLabel)
  }, "frequencies_plot", 1400, 1000)

  output$freqPlot_pdf <- plotDownloadPDF(function() {
    req(rv$tna_result)
    plot_frequencies(rv$tna_result, width = input$freqWidth, hjust = input$freqHjust, show_label = input$freqShowLabel)
  }, "frequencies_plot", 10, 8)

  # Associations Plot
  output$assocPlot_png <- plotDownloadPNG(function() {
    req(rv$tna_result)
    plot_associations(rv$tna_result,
      cut = input$assocCut, minimum = input$assocMinimum,
      label.cex = input$assocNodeLabel, edge.label.cex = input$assocEdgeLabel,
      vsize = input$assocVsize, layout = input$assocLayout, mar = DEFAULT_MAR
    )
  }, "associations_plot", 1200, 1000)

  output$assocPlot_pdf <- plotDownloadPDF(function() {
    req(rv$tna_result)
    plot_associations(rv$tna_result,
      cut = input$assocCut, minimum = input$assocMinimum,
      label.cex = input$assocNodeLabel, edge.label.cex = input$assocEdgeLabel,
      vsize = input$assocVsize, layout = input$assocLayout, mar = DEFAULT_MAR
    )
  }, "associations_plot", 10, 8)

  # Centrality Plot
  output$centralityPlot_png <- plotDownloadPNG(function() {
    req(rv$centrality_result)
    plot(rv$centrality_result, ncol = input$nColsCentralities)
  }, "centrality_plot", 1600, 1200)

  output$centralityPlot_pdf <- plotDownloadPDF(function() {
    req(rv$centrality_result)
    plot(rv$centrality_result, ncol = input$nColsCentralities)
  }, "centrality_plot", 12, 10)

  # Community Plot
  output$communityPlot_png <- plotDownloadPNG(function() {
    req(rv$community_result)
    plot(rv$community_result,
      cut = input$cutCom, minimum = input$minimumCom,
      label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
      vsize = input$vsizeCom, layout = input$layoutCom, mar = DEFAULT_MAR
    )
  }, "community_plot", 1200, 1000)

  output$communityPlot_pdf <- plotDownloadPDF(function() {
    req(rv$community_result)
    plot(rv$community_result,
      cut = input$cutCom, minimum = input$minimumCom,
      label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
      vsize = input$vsizeCom, layout = input$layoutCom, mar = DEFAULT_MAR
    )
  }, "community_plot", 10, 8)

  # Edge Betweenness Plot
  output$edgeBetPlot_png <- plotDownloadPNG(function() {
    req(rv$tna_result)
    plot(betweenness_network(rv$tna_result),
      cut = input$cutEbet, minimum = input$minimumEbet,
      label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
      vsize = input$vsizeEbet, layout = input$layoutEbet, mar = DEFAULT_MAR
    )
  }, "edge_betweenness", 1200, 1000)

  output$edgeBetPlot_pdf <- plotDownloadPDF(function() {
    req(rv$tna_result)
    plot(betweenness_network(rv$tna_result),
      cut = input$cutEbet, minimum = input$minimumEbet,
      label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
      vsize = input$vsizeEbet, layout = input$layoutEbet, mar = DEFAULT_MAR
    )
  }, "edge_betweenness", 10, 8)

  # Cliques Plot
  output$cliquesPlot_png <- plotDownloadPNG(function() {
    req(rv$cliques_result, input$cliqueSelect)
    if (input$cliqueSelect == "") {
      return()
    }
    plot(rv$cliques_result,
      first = as.integer(input$cliqueSelect), n = 1, ask = FALSE,
      cut = input$cutClique, minimum = input$minimumClique, label.cex = input$node.labelClique,
      edge.label.cex = input$edge.labelClique, vsize = input$vsizeClique, layout = input$layoutClique, mar = DEFAULT_MAR
    )
  }, "cliques_plot", 1200, 1000)

  output$cliquesPlot_pdf <- plotDownloadPDF(function() {
    req(rv$cliques_result, input$cliqueSelect)
    if (input$cliqueSelect == "") {
      return()
    }
    plot(rv$cliques_result,
      first = as.integer(input$cliqueSelect), n = 1, ask = FALSE,
      cut = input$cutClique, minimum = input$minimumClique, label.cex = input$node.labelClique,
      edge.label.cex = input$edge.labelClique, vsize = input$vsizeClique, layout = input$layoutClique, mar = DEFAULT_MAR
    )
  }, "cliques_plot", 10, 8)

  # Comparison Plot
  output$comparisonPlot_png <- plotDownloadPNG(function() {
    req(rv$data, input$type, input$compareSelect, input$group1, input$group2)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    if (input$compare_sig) {
      permtest <- permutation_test(group_tnad[[input$group1]], group_tnad[[input$group2]],
        iter = input$iterPerm, paired = input$pairedPerm, level = input$levelPerm
      )
      plot(permtest,
        cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup, mar = DEFAULT_MAR
      )
    } else {
      plot_compare(group_tnad[[input$group1]], group_tnad[[input$group2]],
        cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup,
        posCol = "darkblue", negCol = "red", mar = DEFAULT_MAR
      )
    }
  }, "comparison_plot", 1200, 1000)

  output$comparisonPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data, input$type, input$compareSelect, input$group1, input$group2)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    if (input$compare_sig) {
      permtest <- permutation_test(group_tnad[[input$group1]], group_tnad[[input$group2]],
        iter = input$iterPerm, paired = input$pairedPerm, level = input$levelPerm
      )
      plot(permtest,
        cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup, mar = DEFAULT_MAR
      )
    } else {
      plot_compare(group_tnad[[input$group1]], group_tnad[[input$group2]],
        cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup,
        posCol = "darkblue", negCol = "red", mar = DEFAULT_MAR
      )
    }
  }, "comparison_plot", 10, 8)

  # Mosaic Plot
  output$mosaicPlot_png <- plotDownloadPNG(function() {
    req(rv$data, rv$tna_result, input$type, input$compareSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    plot_mosaic(group_tnad)
  }, "mosaic_plot", 2000, 1400)

  output$mosaicPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data, rv$tna_result, input$type, input$compareSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    plot_mosaic(group_tnad)
  }, "mosaic_plot", 14, 10)

  # Group Centralities Plot
  output$groupCentralitiesPlot_png <- plotDownloadPNG(function() {
    req(rv$data, rv$tna_result, input$type, input$compareSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    plot(centralities(group_tnad,
      measures = input$centralitiesChoiceGroup,
      normalize = input$normalizeGroup, loops = input$loopsGroup
    ), ncol = input$nColsCentralitiesGroup)
  }, "group_centralities", 1600, 1200)

  output$groupCentralitiesPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data, rv$tna_result, input$type, input$compareSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    plot(centralities(group_tnad,
      measures = input$centralitiesChoiceGroup,
      normalize = input$normalizeGroup, loops = input$loopsGroup
    ), ncol = input$nColsCentralitiesGroup)
  }, "group_centralities", 12, 10)

  # Group Networks Plot
  output$groupNetPlot_png <- plotDownloadPNG(function() {
    req(rv$data, rv$tna_result, input$type, input$groupNetSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$groupNetSelect)
    n_groups <- length(group_tnad)
    ncol <- input$groupNetNcol %||% 2
    nrow <- input$groupNetNrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(group_tnad)
    for (i in seq_along(group_tnad)) {
      plot(group_tnad[[i]],
        title = group_names[i], cut = input$groupNetCut, minimum = input$groupNetMinimum,
        label.cex = input$groupNetNodeLabel, edge.label.cex = input$groupNetEdgeLabel,
        vsize = input$groupNetVsize, layout = input$groupNetLayout, mar = DEFAULT_MAR
      )
    }
  }, "group_networks", 1600, 1000)

  output$groupNetPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data, rv$tna_result, input$type, input$groupNetSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$groupNetSelect)
    n_groups <- length(group_tnad)
    ncol <- input$groupNetNcol %||% 2
    nrow <- input$groupNetNrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(group_tnad)
    for (i in seq_along(group_tnad)) {
      plot(group_tnad[[i]],
        title = group_names[i], cut = input$groupNetCut, minimum = input$groupNetMinimum,
        label.cex = input$groupNetNodeLabel, edge.label.cex = input$groupNetEdgeLabel,
        vsize = input$groupNetVsize, layout = input$groupNetLayout, mar = DEFAULT_MAR
      )
    }
  }, "group_networks", 14, 10)

  # Bootstrap Plot
  output$tnaPlotBoot_png <- plotDownloadPNG(function() {
    req(rv$bootstrap_result)
    plot(rv$bootstrap_result,
      cut = input$cutBoot, minimum = input$minimumBoot,
      label.cex = input$node.labelBoot, edge.label.cex = input$edge.labelBoot,
      vsize = input$vsizeBoot, layout = input$layoutBoot, mar = DEFAULT_MAR
    )
  }, "bootstrap_validation", 1200, 1000)

  output$tnaPlotBoot_pdf <- plotDownloadPDF(function() {
    req(rv$bootstrap_result)
    plot(rv$bootstrap_result,
      cut = input$cutBoot, minimum = input$minimumBoot,
      label.cex = input$node.labelBoot, edge.label.cex = input$edge.labelBoot,
      vsize = input$vsizeBoot, layout = input$layoutBoot, mar = DEFAULT_MAR
    )
  }, "bootstrap_validation", 10, 8)

  # Permutation Plot Export
  output$permutationPlot_png <- plotDownloadPNG(function() {
    req(rv$permutation_result)
    n <- length(rv$permutation_result)
    if (n <= 4) {
      par(mfrow = c(2, 2))
    } else if (n <= 6) {
      par(mfrow = c(2, 3))
    } else {
      ncol <- ceiling(sqrt(n))
      nrow <- ceiling(n / ncol)
      par(mfrow = c(nrow, ncol))
    }
    plot(rv$permutation_result)
  }, "permutation_test", 1200, 1000)

  output$permutationPlot_pdf <- plotDownloadPDF(function() {
    req(rv$permutation_result)
    n <- length(rv$permutation_result)
    if (n <= 4) {
      par(mfrow = c(2, 2))
    } else if (n <= 6) {
      par(mfrow = c(2, 3))
    } else {
      ncol <- ceiling(sqrt(n))
      nrow <- ceiling(n / ncol)
      par(mfrow = c(nrow, ncol))
    }
    plot(rv$permutation_result)
  }, "permutation_test", 10, 8)

  # ==========================================================================
  # GROUP MODE - Export Handlers
  # ==========================================================================

  # Group Mode - Visualization Export
  output$gm_visPlot_png <- plotDownloadPNG(function() {
    req(rv$gm_group_tna)
    n_groups <- length(rv$gm_group_tna)
    ncol <- input$gm_ncol %||% 2
    nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(rv$gm_group_tna)
    for (i in seq_along(rv$gm_group_tna)) {
      plot(rv$gm_group_tna[[i]],
        title = group_names[i], cut = input$gm_vis_cut,
        minimum = input$gm_vis_minimum, label.cex = input$`gm_vis_node.label`,
        edge.label.cex = input$`gm_vis_edge.label`, vsize = input$gm_vis_vsize,
        layout = input$gm_vis_layout, mar = DEFAULT_MAR
      )
    }
  }, "gm_visualization", 1600, 1000)

  output$gm_visPlot_pdf <- plotDownloadPDF(function() {
    req(rv$gm_group_tna)
    n_groups <- length(rv$gm_group_tna)
    ncol <- input$gm_ncol %||% 2
    nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(rv$gm_group_tna)
    for (i in seq_along(rv$gm_group_tna)) {
      plot(rv$gm_group_tna[[i]],
        title = group_names[i], cut = input$gm_vis_cut,
        minimum = input$gm_vis_minimum, label.cex = input$`gm_vis_node.label`,
        edge.label.cex = input$`gm_vis_edge.label`, vsize = input$gm_vis_vsize,
        layout = input$gm_vis_layout, mar = DEFAULT_MAR
      )
    }
  }, "gm_visualization", 14, 10)

  # Group Mode - Sequences Export
  output$gm_seqPlot_png <- plotDownloadPNG(function() {
    req(rv$gm_data, input$gm_groupVar)
    args <- list(
      x = rv$gm_data, type = input$gm_seq_type, group = input$gm_groupVar,
      ncol = input$gm_ncol %||% 2, nrow = input$gm_nrow %||% 2
    )
    if (input$gm_seq_type == "distribution") {
      args$scale <- input$gm_seq_scale
      args$geom <- input$gm_seq_geom
    }
    do.call(plot_sequences, args)
  }, "gm_sequences", 1600, 1200)

  output$gm_seqPlot_pdf <- plotDownloadPDF(function() {
    req(rv$gm_data, input$gm_groupVar)
    args <- list(
      x = rv$gm_data, type = input$gm_seq_type, group = input$gm_groupVar,
      ncol = input$gm_ncol %||% 2, nrow = input$gm_nrow %||% 2
    )
    if (input$gm_seq_type == "distribution") {
      args$scale <- input$gm_seq_scale
      args$geom <- input$gm_seq_geom
    }
    do.call(plot_sequences, args)
  }, "gm_sequences", 12, 10)

  # Group Mode - Frequencies Export
  output$gm_freqPlot_png <- plotDownloadPNG(function() {
    req(rv$gm_group_tna)
    n_groups <- length(rv$gm_group_tna)
    ncol_val <- input$gm_ncol %||% 2
    nrow_val <- input$gm_nrow %||% ceiling(n_groups / ncol_val)
    plot_frequencies(rv$gm_group_tna,
      width = input$gm_freq_width,
      hjust = input$gm_freq_hjust, show_label = input$gm_freq_showLabel,
      ncol = ncol_val, nrow = nrow_val
    )
  }, "gm_frequencies", 1600, 1000)

  output$gm_freqPlot_pdf <- plotDownloadPDF(function() {
    req(rv$gm_group_tna)
    n_groups <- length(rv$gm_group_tna)
    ncol_val <- input$gm_ncol %||% 2
    nrow_val <- input$gm_nrow %||% ceiling(n_groups / ncol_val)
    plot_frequencies(rv$gm_group_tna,
      width = input$gm_freq_width,
      hjust = input$gm_freq_hjust, show_label = input$gm_freq_showLabel,
      ncol = ncol_val, nrow = nrow_val
    )
  }, "gm_frequencies", 12, 10)

  # Group Mode - Centralities Export
  output$gm_centPlot_png <- plotDownloadPNG(function() {
    req(rv$gm_group_tna)
    group_tnad <- rv$gm_group_tna
    cent_result <- centralities(group_tnad,
      measures = input$gm_cent_measures,
      normalize = input$gm_cent_normalize, loops = input$gm_cent_loops
    )
    plot(cent_result, ncol = input$gm_cent_plotNcol)
  }, "gm_centralities", 1600, 1200)

  output$gm_centPlot_pdf <- plotDownloadPDF(function() {
    req(rv$gm_group_tna)
    group_tnad <- rv$gm_group_tna
    cent_result <- centralities(group_tnad,
      measures = input$gm_cent_measures,
      normalize = input$gm_cent_normalize, loops = input$gm_cent_loops
    )
    plot(cent_result, ncol = input$gm_cent_plotNcol)
  }, "gm_centralities", 12, 10)

  # Group Mode - Communities Export
  output$gm_commPlot_png <- plotDownloadPNG(function() {
    req(rv$gm_group_tna)
    n_groups <- length(rv$gm_group_tna)
    ncol <- input$gm_ncol %||% 2
    nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(rv$gm_group_tna)
    for (i in seq_along(rv$gm_group_tna)) {
      comm <- tna::communities(rv$gm_group_tna[[i]], gamma = input$gm_comm_gamma)
      plot(comm,
        title = group_names[i], method = input$gm_comm_algorithm, mar = DEFAULT_MAR,
        cut = input$gm_comm_cut, minimum = input$gm_comm_minimum,
        label.cex = input$`gm_comm_node.label`, edge.label.cex = input$`gm_comm_edge.label`,
        vsize = input$gm_comm_vsize, layout = input$gm_comm_layout
      )
    }
  }, "gm_communities", 1600, 1000)

  output$gm_commPlot_pdf <- plotDownloadPDF(function() {
    req(rv$gm_group_tna)
    n_groups <- length(rv$gm_group_tna)
    ncol <- input$gm_ncol %||% 2
    nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(rv$gm_group_tna)
    for (i in seq_along(rv$gm_group_tna)) {
      comm <- tna::communities(rv$gm_group_tna[[i]], gamma = input$gm_comm_gamma)
      plot(comm,
        title = group_names[i], method = input$gm_comm_algorithm, mar = DEFAULT_MAR,
        cut = input$gm_comm_cut, minimum = input$gm_comm_minimum,
        label.cex = input$`gm_comm_node.label`, edge.label.cex = input$`gm_comm_edge.label`,
        vsize = input$gm_comm_vsize, layout = input$gm_comm_layout
      )
    }
  }, "gm_communities", 14, 10)

  # Group Mode - Cliques Export
  output$gm_cliqPlot_png <- plotDownloadPNG(function() {
    req(rv$gm_cliques)
    n_groups <- length(rv$gm_group_tna)
    ncol <- input$gm_ncol %||% 2
    nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(rv$gm_cliques)
    for (i in seq_along(rv$gm_cliques)) {
      plot(rv$gm_cliques[[i]],
        title = group_names[i], first = 1, n = 1, ask = FALSE,
        cut = input$gm_cliq_cut, minimum = input$gm_cliq_minimum,
        label.cex = input$`gm_cliq_node.label`, edge.label.cex = input$`gm_cliq_edge.label`,
        vsize = input$gm_cliq_vsize, layout = input$gm_cliq_layout, mar = DEFAULT_MAR
      )
    }
  }, "gm_cliques", 1600, 1000)

  output$gm_cliqPlot_pdf <- plotDownloadPDF(function() {
    req(rv$gm_cliques)
    n_groups <- length(rv$gm_group_tna)
    ncol <- input$gm_ncol %||% 2
    nrow <- input$gm_nrow %||% ceiling(n_groups / ncol)
    par(mfrow = c(nrow, ncol))
    group_names <- names(rv$gm_cliques)
    for (i in seq_along(rv$gm_cliques)) {
      plot(rv$gm_cliques[[i]],
        title = group_names[i], first = 1, n = 1, ask = FALSE,
        cut = input$gm_cliq_cut, minimum = input$gm_cliq_minimum,
        label.cex = input$`gm_cliq_node.label`, edge.label.cex = input$`gm_cliq_edge.label`,
        vsize = input$gm_cliq_vsize, layout = input$gm_cliq_layout, mar = DEFAULT_MAR
      )
    }
  }, "gm_cliques", 14, 10)
}

# ============================================================================
# Run Application
# ============================================================================

shinyApp(ui = ui, server = server)
