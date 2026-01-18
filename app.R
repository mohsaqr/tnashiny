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

  observeEvent(input$stored_auth, {
    stored <- input$stored_auth
    if (!is.null(stored) && !auth$logged_in) {
      message("=== RESTORING SESSION FROM STORAGE ===")

      tryCatch({
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

      }, error = function(e) {
        message("Session restore failed: ", e$message)
        # Clear invalid stored auth
        session$sendCustomMessage("clearAuth", list())
      })
    }
  }, ignoreNULL = FALSE, once = TRUE)

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

      tryCatch({
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
      }, error = function(e) {
        showNotification(
          paste("Login failed:", e$message),
          type = "error",
          duration = 5
        )
        updateQueryString("?", mode = "replace", session = session)
      })
    }
  })

  # --------------------------------------------------------------------------
  # Main UI Rendering
  # --------------------------------------------------------------------------

  output$main_ui <- renderUI({
    tryCatch({
      if (auth$logged_in) {
        # Show main dashboard
        main_dashboard_ui(auth$user_name, auth$user_email, auth$user_picture)
      } else {
        # Show login page
        login_page_ui()
      }
    }, error = function(e) {
      message("ERROR in main_ui: ", e$message)
      div(
        style = "padding: 50px; text-align: center;",
        h2("Error Loading Application"),
        p("An error occurred while loading the application."),
        p(style = "color: red;", e$message),
        actionButton("reload_app", "Reload Application", class = "btn btn-primary",
                     onclick = "localStorage.removeItem('tna_auth'); location.reload();")
      )
    })
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

    tryCatch({
      auth_url <- build_auth_url(session)
      message("Auth URL: ", substr(auth_url, 1, 100), "...")
      message("Redirecting to Google...")
      runjs(sprintf('window.location.href = "%s";', auth_url))
    }, error = function(e) {
      message("ERROR building auth URL: ", e$message)
      showNotification(paste("Error:", e$message), type = "error")
    })
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
              column(12, align = "center",
                actionLink("menu_my_analyses", tagList(icon("folder-open"), " My Analyses")),
                tags$br(),
                actionLink("menu_open_drive", tagList(icon("google-drive"), " Open TNA Folder"))
              )
            )
          ),
          tags$li(
            class = "user-footer",
            actionButton("logout_btn", tagList(icon("sign-out-alt"), " Sign Out"),
                         class = "btn btn-default btn-flat btn-block")
          )
        )
      )
    )

    # Add logo to header (safely modify structure)
    tryCatch({
      logo <- tags$span(
        tags$a(href = "https://sonsoles.me/tna",
               tags$img(src = "logo.png", height = "44", width = "40")),
        "TNA"
      )
      if (length(db_header$children) >= 2 && !is.null(db_header$children[[2]])) {
        db_header$children[[2]]$children <- logo
      }
    }, error = function(e) {
      message("Could not modify header logo: ", e$message)
    })

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
          menuItem("Centrality Measures", tabName = "centrality", icon = icon("chart-line")),
          menuItem("Community Detection", tabName = "communities", icon = icon("users")),
          menuItem("Edge Betweenness", tabName = "edgebet", icon = icon("people-arrows")),
          menuItem("Cliques", tabName = "cliques", icon = icon("sitemap")),
          menuItem("Comparison", tabName = "comparison", icon = icon("balance-scale")),
          menuItem("Validation", tabName = "bootstrap", icon = icon("check-circle"))
        )
      ),
      dashboardBody(
        tags$html(lang = "en"),
        tags$link(rel = "stylesheet", type = "text/css", href = "custom.css"),

        # Toolbar with Save/Load/Export buttons
        div(
          class = "content-toolbar",
          style = "padding: 10px 15px; background: #f4f4f4; border-bottom: 1px solid #ddd; margin-bottom: 10px;",
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
                    radioButtons("inputType", "Input Type:", selected = character(0),
                      choices = c("Sample data" = "sample", "Sequence Data" = "sequence",
                                  "Long Data" = "long", "Transition Matrix" = "matrix")),
                    conditionalPanel("input.inputType == 'sequence'",
                      fileInput("fileInput", "Upload data file (sequence or wide data)")),
                    conditionalPanel("input.inputType == 'long'",
                      fileInput("longInput", "Upload long data"),
                      selectInput("longAction", "Action:", choices = NULL, selectize = FALSE),
                      selectInput("longActor", "Actor:", choices = NULL, selectize = FALSE),
                      selectInput("longTime", "Time:", choices = NULL, selectize = FALSE),
                      selectInput("longOrder", "Order:", choices = NULL, selectize = FALSE),
                      numericInput("longThreshold", "Threshold:", min = 0, value = 900, step = 1),
                      textInput("longDate", "Date format:", placeholder = "Not mandatory")),
                    conditionalPanel("input.inputType == 'matrix'",
                      fileInput("matrixInput", "Upload transition matrix")),
                    selectInput("type", "Analysis Type:", choices = c("relative", "frequency", "co-occurrence")),
                    actionButton("analyze", "Analyze", class = "btn-primary")
                  )
                )
              ),
              column(
                width = 9,
                fluidRow(
                  conditionalPanel("!(input.inputType)",
                    fluidRow(box(width = 12, title = "Welcome to TNA!",
                      fluidRow(column(12, p("Select the format of your data on the left panel or use our example data."))),
                      fluidRow(
                        column(4, span("Sequence Data", class = "datatype"),
                          img(src = "wide.png", width = "100%", class = "thumb"),
                          p("Wide-format data stores each time point in a separate column.")),
                        column(4, span("Long Data", class = "datatype"),
                          img(src = "long.png", width = "100%", class = "thumb"),
                          p("Long-format data stacks repeated measurements in rows.")),
                        column(4, span("Transition Matrix", class = "datatype"),
                          img(src = "matrix.png", width = "100%", class = "thumb"),
                          p("You can also upload directly a transition probability matrix."))
                      )
                    ))
                  ),
                  conditionalPanel("input.inputType",
                    box(title = "Data Preview", width = 12,
                      DTOutput("dataPreview"),
                      conditionalPanel("input.inputType != 'sample' & !input.dataPreview_state",
                        span(icon("circle-info", class = "text-info"), "No data selected yet")),
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
              box(width = 3,
                div(class = "box-header-with-export",
                  h3(class = "box-title", "Summary Statistics"),
                  tableExportButtons("summaryStats")
                ),
                tableOutput("summaryStats")
              ),
              box(width = 4,
                div(class = "box-header-with-export",
                  h3(class = "box-title", "Initial Probabilities"),
                  tableExportButtons("initialProbs")
                ),
                DTOutput("initialProbs")
              ),
              box(width = 5,
                div(class = "box-header-with-export",
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
                fluidRow(box(title = "Settings", width = 12,
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
                fluidRow(box(width = 12,
                  div(class = "box-header-with-export",
                    h3(class = "box-title", "Visualization"),
                    plotExportButtons("tnaPlot")
                  ),
                  div(jqui_resizable(plotOutput("tnaPlot", width = "600px", height = "600px"),
                    options = list(ghost = TRUE, helper = "resizable-helper")), align = "center")
                ))
              )
            )
          ),

          # Centrality Tab
          tabItem(
            tabName = "centrality",
            fluidRow(box(fluidRow(
              column(width = 6, selectInput("centralitiesChoice", "Centralities", multiple = TRUE,
                choices = c("OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                            "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"),
                selected = c("OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                             "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"))),
              column(width = 2, tags$label("Properties"),
                checkboxInput("loops", "Loops?", value = FALSE),
                checkboxInput("normalize", "Normalize?", value = FALSE), class = "checkboxcentralities"),
              column(width = 2, numericInput("nColsCentralities", "Columns", 3, min = 1, max = 9, step = 1))
            ), width = 12)),
            fluidRow(box(width = 12,
              div(class = "box-header-with-export",
                h3(class = "box-title", "Centrality Measures"),
                div(style = "display: flex; gap: 10px;",
                  span("Table:", style = "color: #666; font-size: 0.9em;"), tableExportButtons("centralityPrint"),
                  span("Plot:", style = "color: #666; font-size: 0.9em; margin-left: 15px;"), plotExportButtons("centralityPlot")
                )
              ),
              div(tableOutput("centralityPrint"), align = "center", width = 12),
              div(jqui_resizable(plotOutput("centralityPlot", width = "800px", height = "800px"),
                options = list(ghost = TRUE, helper = "resizable-helper")), align = "center", width = 12)
            ))
          ),

          # Communities Tab
          tabItem(
            tabName = "communities",
            fluidRow(
              column(width = 3, fluidRow(
                box(title = "Community Detection Settings", width = 12,
                  selectInput("communityAlgorithm", "Choose Algorithm:", choices = "spinglass"),
                  numericInput("gamma", "Gamma:", value = 1, min = 0, max = 100)),
                box(title = "Plotting Settings", width = 12,
                  sliderInput("cutCom", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                  sliderInput("minimumCom", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                  sliderInput("edge.labelCom", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                  sliderInput("vsizeCom", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                  sliderInput("node.labelCom", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                  selectInput("layoutCom", "Layout", choices = c("circle", "spring"), selected = "circle"))
              )),
              box(width = 9,
                div(class = "box-header-with-export",
                  h3(class = "box-title", "Community Detection Results"),
                  plotExportButtons("communityPlot")
                ),
                div(jqui_resizable(plotOutput("communityPlot", width = "600px", height = "600px"),
                  options = list(ghost = TRUE, helper = "resizable-helper")), align = "center", width = 12))
            )
          ),

          # Edge Betweenness Tab
          tabItem(
            tabName = "edgebet",
            fluidRow(
              column(width = 3, fluidRow(box(title = "Settings", width = 12,
                sliderInput("cutEbet", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                sliderInput("minimumEbet", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                sliderInput("edge.labelEbet", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                sliderInput("vsizeEbet", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                sliderInput("node.labelEbet", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                selectInput("layoutEbet", "Layout", choices = c("circle", "spring"), selected = "circle")
              ))),
              column(width = 9, fluidRow(box(width = 12,
                div(class = "box-header-with-export",
                  h3(class = "box-title", "Edge Betweenness"),
                  plotExportButtons("edgeBetPlot")
                ),
                div(jqui_resizable(plotOutput("edgeBetPlot", width = "600px", height = "600px"),
                  options = list(ghost = TRUE, helper = "resizable-helper")), align = "center")
              )))
            )
          ),

          # Cliques Tab
          tabItem(
            tabName = "cliques",
            fluidRow(
              column(width = 3, fluidRow(
                box(title = "Clique Settings", width = 12,
                  numericInput("cliqueSize", "Clique Size (n):", value = 3, min = 2, max = 10),
                  numericInput("cliqueThreshold", "Threshold:", value = 0, min = 0, max = 1, step = 0.05),
                  actionButton("findCliques", "Find Cliques", class = "btn-primary")),
                box(title = "Plotting Settings", width = 12,
                  sliderInput("cutClique", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                  sliderInput("minimumClique", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                  sliderInput("edge.labelClique", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                  sliderInput("vsizeClique", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                  sliderInput("node.labelClique", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                  selectInput("layoutClique", "Layout", choices = c("circle", "spring"), selected = "circle"))
              )),
              column(width = 9, fluidRow(box(width = 12,
                div(class = "box-header-with-export",
                  h3(class = "box-title", "Cliques Found"),
                  plotExportButtons("cliquesPlot")
                ),
                selectInput("cliqueSelect", "Choose Clique:", choices = NULL, width = "30%"),
                div(jqui_resizable(plotOutput("cliquesPlot"),
                  options = list(ghost = TRUE, helper = "resizable-helper")), align = "center", width = 12)
              )))
            )
          ),

          # Comparison Tab
          tabItem(
            tabName = "comparison",
            conditionalPanel("(input.inputType == 'long') | (input.inputType == 'sample')",
              fluidRow(
                column(width = 3, fluidRow(
                  box(title = "Comparison Settings", width = 12,
                    selectInput("compareSelect", "Choose grouping column:", choices = NULL),
                    selectInput("group1", "Choose group 1:", choices = NULL),
                    selectInput("group2", "Choose group 2:", choices = NULL),
                    input_switch("compare_sig", "Permutation test"),
                    conditionalPanel("input.compare_sig",
                      numericInput("iterPerm", "Iteration:", min = 0, max = 10000, value = 1000, step = 100),
                      numericInput("levelPerm", "Level:", min = 0, max = 1, value = 0.05, step = 0.01),
                      input_switch("pairedPerm", "Paired test"))),
                  box(title = "Plotting Settings", width = 12,
                    sliderInput("cutGroup", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                    sliderInput("minimumGroup", "Minimum Value", min = 0, max = 1, value = 0, step = 0.01),
                    sliderInput("edge.labelGroup", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                    sliderInput("vsizeGroup", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                    sliderInput("node.labelGroup", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                    selectInput("layoutGroup", "Layout", choices = c("circle", "spring"), selected = "circle"))
                )),
                column(width = 9, fluidRow(
                  tabBox(id = "tabset1", width = 12,
                    tabPanel("Difference",
                      div(class = "box-header-with-export", style = "margin-bottom: 10px;",
                        span("Export:", style = "color: #666;"), plotExportButtons("comparisonPlot")),
                      div(jqui_resizable(plotOutput("comparisonPlot", width = "600px", height = "600px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")), align = "center")),
                    tabPanel("Mosaic",
                      div(class = "box-header-with-export", style = "margin-bottom: 10px;",
                        span("Export:", style = "color: #666;"), plotExportButtons("mosaicPlot")),
                      div(jqui_resizable(plotOutput("mosaicPlot", width = "1400px", height = "900px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")), align = "center")),
                    tabPanel("Centralities",
                      fluidRow(box(fluidRow(
                        column(width = 6, selectInput("centralitiesChoiceGroup", "Centralities", multiple = TRUE,
                          choices = c("OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                                      "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"),
                          selected = c("OutStrength", "InStrength", "ClosenessIn", "ClosenessOut", "Closeness",
                                       "BetweennessRSP", "Betweenness", "Diffusion", "Clustering"))),
                        column(width = 2, tags$label("Properties"),
                          checkboxInput("loopsGroup", "Loops?", value = FALSE),
                          checkboxInput("normalizeGroup", "Normalize?", value = FALSE), class = "checkboxcentralities"),
                        column(width = 2, numericInput("nColsCentralitiesGroup", "Columns", 3, min = 1, max = 9, step = 1))
                      ), width = 12)),
                      div(class = "box-header-with-export", style = "margin-bottom: 10px;",
                        span("Export:", style = "color: #666;"), plotExportButtons("groupCentralitiesPlot")),
                      div(jqui_resizable(plotOutput("groupCentralitiesPlot", width = "900px", height = "600px"),
                        options = list(ghost = TRUE, helper = "resizable-helper")), align = "center"))
                  )
                ))
              )
            ),
            conditionalPanel("input.inputType != 'long' & input.inputType != 'sample'",
              box(span(icon("circle-info", class = "text-danger"), "Comparison operations are only supported in long data"), width = 7))
          ),

          # Bootstrap/Validation Tab
          tabItem(
            tabName = "bootstrap",
            conditionalPanel("input.inputType != 'matrix'",
              fluidRow(
                column(width = 3, fluidRow(
                  box(title = "Bootstrapping", width = 12,
                    numericInput("iterBoot", "Iteration:", min = 0, max = 10000, value = 1000, step = 100),
                    numericInput("levelBoot", "Level:", min = 0, max = 1, value = 0.05, step = 0.01),
                    selectInput("methodBoot", "Method", choices = c("stability", "threshold"), selected = "stability"),
                    conditionalPanel("input.methodBoot == 'threshold'",
                      numericInput("thresBoot", "Threshold:", min = 0, max = 1, value = 0.1, step = 0.01)),
                    conditionalPanel("input.methodBoot == 'stability'",
                      h4("Consistency Range"),
                      numericInput("constLowerBoot", "Lower:", min = 0, max = 10, value = 0.75, step = 0.01),
                      numericInput("constUpperBoot", "Upper:", min = 0, max = 10, value = 1.25, step = 0.01)),
                    actionButton("bootstrapButton", "Bootstrap", class = "btn-primary")),
                  box(title = "Settings", width = 12,
                    sliderInput("cutBoot", "Cut Value", min = 0, max = 1, value = 0.1, step = 0.01),
                    sliderInput("minimumBoot", "Minimum Value", min = 0, max = 1, value = 0.05, step = 0.01),
                    sliderInput("edge.labelBoot", "Edge label size", min = 0, max = 10, value = 1, step = 0.1),
                    sliderInput("vsizeBoot", "Node size", min = 0, max = 30, value = 8, step = 0.1),
                    sliderInput("node.labelBoot", "Node label size", min = 0, max = 10, value = 1, step = 0.1),
                    selectInput("layoutBoot", "Layout", choices = c("circle", "spring"), selected = "circle"))
                )),
                column(width = 9, fluidRow(box(width = 12,
                  div(class = "box-header-with-export",
                    h3(class = "box-title", "Bootstrap Validation"),
                    plotExportButtons("tnaPlotBoot")
                  ),
                  div(jqui_resizable(plotOutput("tnaPlotBoot", width = "600px", height = "600px"),
                    options = list(ghost = TRUE, helper = "resizable-helper")), align = "center")
                )))
              )
            ),
            conditionalPanel("input.inputType == 'matrix'",
              box(span(icon("circle-info", class = "text-danger"), "Validation operations are only supported when the full data is provided"), width = 7))
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
    bootstrap_result = NULL
  )

  mar <- DEFAULT_MAR

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
        div(class = "save-info", icon("info-circle"),
          span("Your analysis will be saved to your Google Drive in the TNA_App/analyses folder."))
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
      settings = list(type = input$type, cut = input$cut, minimum = input$minimum,
                      layout = input$layout, vsize = input$vsize)
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
      return(datatable(data.frame(Message = "No saved analyses found"), options = list(dom = 't'), rownames = FALSE))
    }
    display_df <- data.frame(
      Name = df$name,
      Modified = sapply(df$modified, format_date_display),
      Size = sapply(df$size, format_file_size),
      check.names = FALSE
    )
    datatable(display_df, selection = "single", options = list(pageLength = 5, dom = 'tp'), rownames = FALSE)
  })

  output$load_selected_info <- renderUI({
    sel <- input$load_analyses_table_rows_selected
    df <- analyses_list()
    if (length(sel) == 0 || nrow(df) == 0) return(div(class = "text-muted", "Select an analysis"))
    row <- df[sel, ]
    div(class = "analysis-preview",
      h5(row$name),
      p(tags$strong("File: "), row$filename, tags$br(),
        tags$strong("Modified: "), format_date_display(row$modified))
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
          choices = c("Transition Matrix" = "matrix", "Centrality Measures" = "centrality",
                      "Initial Probabilities" = "initial", "Summary Statistics" = "summary"),
          selected = c("matrix")),
        hr(),
        radioButtons("export_format", "Format", choices = c("CSV" = "csv"), selected = "csv", inline = TRUE),
        radioButtons("export_dest", "Destination",
          choices = c("Download" = "download", "Save to Google Drive" = "drive"), selected = "download")
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

  observeEvent(input$inputType, { rv$original <- NULL })

  # Data analysis
  observeEvent(input$analyze, {
    req(input$inputType)
    req(input$type)

    if (input$inputType == "sequence") {
      rv$data <- rv$original
      tryCatch({
        rv$tna_result <- build_model(rv$data, type = req(input$type))
      }, error = function(e) {
        showNotification("There was an error", type = "error", duration = 3)
      })
    } else if (input$inputType == "long") {
      tryCatch({
        action <- rlang::missing_arg()
        actor <- rlang::missing_arg()
        time <- rlang::missing_arg()
        order <- rlang::missing_arg()
        dateformat <- NULL
        thresh <- Inf
        whitelist <- c(".session_id", ".standardized_time", ".session_nr")

        if ((input$longAction != "") && !is.null(input$longAction)) {
          action <- input$longAction
          whitelist <- c(whitelist, action)
        }
        if ((input$longActor != "") && !is.null(input$longActor)) {
          actor <- input$longActor
          whitelist <- c(whitelist, actor)
        }
        if ((input$longTime != "") && !is.null(input$longTime)) {
          time <- input$longTime
          whitelist <- c(whitelist, time)
        }
        if ((input$longOrder != "") && !is.null(input$longOrder)) {
          order <- input$longOrder
          whitelist <- c(whitelist, order)
        }
        if ((input$longDate != "") && !is.null(input$longDate)) {
          dateformat <- input$longDate
        }
        if ((input$longThreshold != "") && !is.null(input$longThreshold)) {
          thresh <- input$longThreshold
        }

        rv$data <- prepare_data(rv$original, action = action, actor = actor,
          time_threshold = thresh, time = time, order = order, custom_format = dateformat)
        rv$tna_result <- build_model(rv$data, type = req(input$type))

        groupchoices <- names(rv$data$meta_data)
        groupchoices <- groupchoices[sapply(groupchoices, \(x) !(x %in% whitelist))]
        updateSelectInput(session, "compareSelect", choices = groupchoices)
      }, error = function(e) {
        showNotification("There was an error", type = "error", duration = 3)
      })
    } else if (input$inputType == "matrix") {
      tryCatch({
        matrix_data <- as.matrix(rv$original)
        rv$data <- matrix_data
        rv$tna_result <- tna(matrix_data)
      }, error = function(e) {
        showNotification("There was an error", type = "error", duration = 3)
      })
    } else if (input$inputType == "sample") {
      tryCatch({
        rv$data <- structure(
          list(long_data = NULL, sequence_data = rv$original,
               meta_data = data.frame(Achiever = c(rep("High", 1000), rep("Low", 1000))),
               statistics = NULL),
          class = "tna_data"
        )
        groupchoices <- names(rv$data$meta_data)
        updateSelectInput(session, "compareSelect", choices = groupchoices)
        rv$tna_result <- build_model(rv$data, type = req(input$type))
        rv$tna_result$data$Achiever <- c(rep("High", 1000), rep("Low", 1000))
      }, error = function(e) {
        showNotification("There was an error", type = "error", duration = 3)
      })
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
  })

  # Data Preview
  output$dataPreview <- renderDT({
    rv$original <- NULL
    if (is.null(input$inputType)) return(NULL)

    if (!is.null(input$longInput) && input$inputType == "long") {
      rv$original <- import(input$longInput$datapath)
      theoptions <- c(Empty = "", names(rv$original))
      updateSelectInput(session, "longAction", choices = theoptions)
      updateSelectInput(session, "longActor", choices = theoptions)
      updateSelectInput(session, "longOrder", choices = theoptions)
      updateSelectInput(session, "longTime", choices = theoptions)
    } else if (!is.null(input$matrixInput) && input$inputType == "matrix") {
      rv$original <- import(input$matrixInput$datapath, row.names = 1)
    } else if (!is.null(input$fileInput) && input$inputType == "sequence") {
      rv$original <- import(input$fileInput$datapath)
    } else if (input$inputType == "sample") {
      rv$original <- group_regulation
    }

    rv$tna_result <- NULL
    rv$centrality_result <- NULL
    rv$cliques_result <- NULL
    rv$clique_plots <- list()
    rv$community_result <- NULL
    rv$bootstrap_result <- NULL

    datatable(rv$original, options = list(scrollX = TRUE))
  })

  output$summary_model <- renderPrint({ rv$tna_result })
  output$summary_boot_model <- renderPrint({ rv$bootstrap_result })
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
  output$centralityPlot <- renderPlot({
    req(rv$tna_result)
    centrality_result <- centralities(rv$tna_result, measures = input$centralitiesChoice,
      normalize = input$normalize, loops = input$loops)
    rv$centrality_result <- centrality_result
    tryCatch({ plot(centrality_result, ncol = input$nColsCentralities) },
      error = function(e) showNotification("Error plotting centralities", type = "error"))
  }, res = 100)

  output$centralityPrint <- renderTable({
    req(rv$centrality_result)
    data.frame(rv$centrality_result)
  })

  # TNA Plot
  output$tnaPlot <- renderPlot({
    req(rv$tna_result)
    tryCatch({
      plot(rv$tna_result, cut = input$cut, minimum = input$minimum, label.cex = input$node.label,
        edge.label.cex = input$edge.label, vsize = input$vsize, layout = input$layout, mar = mar)
    }, error = function(e) showNotification("Error plotting TNA", type = "error"))
  }, res = 600)

  # Edge Betweenness Plot
  output$edgeBetPlot <- renderPlot({
    req(rv$tna_result)
    tryCatch({
      plot(betweenness_network(rv$tna_result), cut = input$cutEbet, minimum = input$minimumEbet,
        label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
        vsize = input$vsizeEbet, layout = input$layoutEbet, mar = mar)
    }, error = function(e) showNotification("Error plotting edge betweenness", type = "error"))
  }, res = 600)

  # Community Plot
  output$communityPlot <- renderPlot({
    req(rv$tna_result)
    rv$community_result <- tna::communities(rv$tna_result, gamma = input$gamma)
    algorithm_choices <- sapply(names(rv$community_result$counts), function(alg) {
      paste0(alg, " (", rv$community_result$counts[[alg]], " communities)")
    })
    choices <- names(algorithm_choices)
    names(choices) <- paste0(names(rv$community_result$counts), " (", rv$community_result$counts, ")")
    updateSelectInput(session, "communityAlgorithm", choices = choices, selected = input$communityAlgorithm)

    tryCatch({
      plot(rv$community_result, method = input$communityAlgorithm, mar = mar, cut = input$cutCom,
        minimum = input$minimumCom, label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
        vsize = input$vsizeCom, layout = input$layoutCom)
    }, error = function(e) showNotification("Error plotting communities", type = "error"))
  }, res = 600)

  # Clique Finding
  observeEvent(input$findCliques, {
    req(rv$tna_result)
    req(input$cliqueSize)
    req(input$cliqueThreshold)

    rv$cliques_result <- tna::cliques(rv$tna_result, size = input$cliqueSize,
      threshold = input$cliqueThreshold, n = 1000)

    if (length(rv$cliques_result$inits) > 0) {
      choices <- seq_along(rv$cliques_result$inits)
      names(choices) <- lapply(rv$cliques_result$inits, \(x) names(x) |> paste(collapse = " - "))
      names(choices) <- paste0("Clique ", choices, ": ", names(choices))
      updateSelectInput(session, "cliqueSelect", choices = choices, selected = 1)
    } else {
      updateSelectInput(session, "cliqueSelect", selected = NULL, choices = NULL)
    }
  })

  output$cliquesPlot <- renderPlot({
    req(rv$cliques_result)
    if (is.null(input$cliqueSelect) || input$cliqueSelect == "") return(NULL)
    tryCatch({
      plot(rv$cliques_result, first = as.integer(input$cliqueSelect), n = 1, ask = FALSE,
        cut = input$cutClique, minimum = input$minimumClique, label.cex = input$node.labelClique,
        edge.label.cex = input$edge.labelClique, vsize = input$vsizeClique, layout = input$layoutClique, mar = mar)
    }, error = function(e) showNotification("Error plotting cliques", type = "error"))
  }, res = 600)

  # Comparison
  observeEvent(input$compareSelect, {
    if (is.null(rv$data$meta_data)) return()
    choices <- unique(data.frame(rv$data$meta_data)[, input$compareSelect])
    updateSelectInput(session, "group1", choices = choices,
      selected = if (!is.null(choices) && length(choices) > 0) choices[1] else rlang::missing_arg())
    updateSelectInput(session, "group2", choices = choices,
      selected = if (!is.null(choices) && length(choices) > 1) choices[2] else rlang::missing_arg())
  })

  output$comparisonPlot <- renderPlot({
    req(rv$data)
    tryCatch({
      group_tnad <- group_model(req(rv$data), type = req(input$type), group = req(input$compareSelect))
      if (input$compare_sig) {
        differentrows <- nrow(group_tnad[[req(input$group1)]]$data) != nrow(group_tnad[[req(input$group2)]]$data)
        permtest <- permutation_test(group_tnad[[req(input$group1)]], group_tnad[[req(input$group2)]],
          iter = input$iterPerm, paired = if (differentrows) FALSE else input$pairedPerm, level = input$levelPerm)
        if (differentrows && input$pairedPerm) {
          showNotification("Paired test cannot be applied - groups have different sizes", type = "warning")
        }
        plot(permtest, cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
          edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup, mar = mar)
      } else {
        plot_compare(group_tnad[[req(input$group1)]], group_tnad[[req(input$group2)]],
          cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
          edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup,
          posCol = "darkblue", negCol = "red", mar = mar)
      }
    }, error = function(e) showNotification("Error in comparison", type = "error"))
  }, res = 600)

  output$mosaicPlot <- renderPlot({
    req(rv$tna_result)
    tryCatch({
      group_tnad <- group_model(req(rv$data), type = req(input$type), group = req(input$compareSelect))
      plot_mosaic(group_tnad)
    }, error = function(e) showNotification("Error plotting mosaic", type = "error"))
  }, res = 100)

  output$groupCentralitiesPlot <- renderPlot({
    req(rv$tna_result)
    tryCatch({
      group_tnad <- group_model(req(rv$data), type = req(input$type), group = req(input$compareSelect))
      plot(centralities(group_tnad, measures = input$centralitiesChoiceGroup,
        normalize = input$normalizeGroup, loops = input$loopsGroup), ncol = input$nColsCentralitiesGroup)
    }, error = function(e) showNotification("Error plotting group centralities", type = "error"))
  }, res = 100)

  # Bootstrap
  observeEvent(input$bootstrapButton, {
    req(rv$tna_result)
    tryCatch({
      boot <- tna::bootstrap(rv$tna_result, iter = input$iterBoot, level = input$levelBoot,
        method = input$methodBoot, threshold = input$thresBoot,
        consistency_range = sort(c(input$constLowerBoot, input$constUpperBoot)))
      rv$bootstrap_result <- prune(rv$tna_result, method = "bootstrap", boot = boot)
    }, error = function(e) showNotification("Error in bootstrap", type = "error"))
  })

  output$tnaPlotBoot <- renderPlot({
    req(rv$bootstrap_result)
    tryCatch({
      plot(rv$bootstrap_result, cut = input$cutBoot, minimum = input$minimumBoot,
        label.cex = input$node.labelBoot, edge.label.cex = input$edge.labelBoot,
        vsize = input$vsizeBoot, layout = input$layoutBoot, mar = mar)
    }, error = function(e) showNotification("Error plotting bootstrap results", type = "error"))
  }, res = 600)

  output$bootstrappedtnaModel <- renderUI({
    if (is.null(rv$bootstrap_result)) NULL else verbatimTextOutput("summary_boot_model")
  })

  # --------------------------------------------------------------------------
  # Export Download Handlers
  # --------------------------------------------------------------------------

  # --- Table Exports ---

  # Summary Stats
  output$summaryStats_csv <- tableDownloadCSV(
    function() { if (!is.null(rv$tna_result)) as.data.frame(summary(rv$tna_result)) else NULL },
    "summary_stats"
  )
  output$summaryStats_xlsx <- tableDownloadXLSX(
    function() { if (!is.null(rv$tna_result)) as.data.frame(summary(rv$tna_result)) else NULL },
    "summary_stats"
  )

  # Initial Probabilities
  output$initialProbs_csv <- tableDownloadCSV(
    function() {
      if (!is.null(rv$tna_result) && !is.null(rv$tna_result$inits)) {
        data.frame(State = names(rv$tna_result$inits), Probability = round(rv$tna_result$inits, 3))
      } else NULL
    },
    "initial_probs"
  )
  output$initialProbs_xlsx <- tableDownloadXLSX(
    function() {
      if (!is.null(rv$tna_result) && !is.null(rv$tna_result$inits)) {
        data.frame(State = names(rv$tna_result$inits), Probability = round(rv$tna_result$inits, 3))
      } else NULL
    },
    "initial_probs"
  )

  # Transition Matrix
  output$transitionMatrix_csv <- tableDownloadCSV(
    function() { if (!is.null(rv$tna_result)) round(rv$tna_result$weights, 3) else NULL },
    "transition_matrix"
  )
  output$transitionMatrix_xlsx <- tableDownloadXLSX(
    function() { if (!is.null(rv$tna_result)) round(rv$tna_result$weights, 3) else NULL },
    "transition_matrix"
  )

  # Centrality Measures
  output$centralityPrint_csv <- tableDownloadCSV(
    function() { rv$centrality_result },
    "centrality_measures"
  )
  output$centralityPrint_xlsx <- tableDownloadXLSX(
    function() { rv$centrality_result },
    "centrality_measures"
  )

  # --- Plot Exports ---

  # TNA Plot
  output$tnaPlot_png <- plotDownloadPNG(function() {
    req(rv$tna_result)
    plot(rv$tna_result, cut = input$cut, minimum = input$minimum,
      label.cex = input$node.label, edge.label.cex = input$edge.label,
      vsize = input$vsize, layout = input$layout, mar = DEFAULT_MAR)
  }, "tna_network", 1200, 1000)

  output$tnaPlot_pdf <- plotDownloadPDF(function() {
    req(rv$tna_result)
    plot(rv$tna_result, cut = input$cut, minimum = input$minimum,
      label.cex = input$node.label, edge.label.cex = input$edge.label,
      vsize = input$vsize, layout = input$layout, mar = DEFAULT_MAR)
  }, "tna_network", 10, 8)

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
    plot(rv$community_result, cut = input$cutCom, minimum = input$minimumCom,
      label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
      vsize = input$vsizeCom, layout = input$layoutCom, mar = DEFAULT_MAR)
  }, "community_plot", 1200, 1000)

  output$communityPlot_pdf <- plotDownloadPDF(function() {
    req(rv$community_result)
    plot(rv$community_result, cut = input$cutCom, minimum = input$minimumCom,
      label.cex = input$node.labelCom, edge.label.cex = input$edge.labelCom,
      vsize = input$vsizeCom, layout = input$layoutCom, mar = DEFAULT_MAR)
  }, "community_plot", 10, 8)

  # Edge Betweenness Plot
  output$edgeBetPlot_png <- plotDownloadPNG(function() {
    req(rv$tna_result)
    plot(betweenness_network(rv$tna_result), cut = input$cutEbet, minimum = input$minimumEbet,
      label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
      vsize = input$vsizeEbet, layout = input$layoutEbet, mar = DEFAULT_MAR)
  }, "edge_betweenness", 1200, 1000)

  output$edgeBetPlot_pdf <- plotDownloadPDF(function() {
    req(rv$tna_result)
    plot(betweenness_network(rv$tna_result), cut = input$cutEbet, minimum = input$minimumEbet,
      label.cex = input$node.labelEbet, edge.label.cex = input$edge.labelEbet,
      vsize = input$vsizeEbet, layout = input$layoutEbet, mar = DEFAULT_MAR)
  }, "edge_betweenness", 10, 8)

  # Cliques Plot
  output$cliquesPlot_png <- plotDownloadPNG(function() {
    req(rv$cliques_result, input$cliqueSelect)
    if (input$cliqueSelect == "") return()
    plot(rv$cliques_result, first = as.integer(input$cliqueSelect), n = 1, ask = FALSE,
      cut = input$cutClique, minimum = input$minimumClique, label.cex = input$node.labelClique,
      edge.label.cex = input$edge.labelClique, vsize = input$vsizeClique, layout = input$layoutClique, mar = DEFAULT_MAR)
  }, "cliques_plot", 1200, 1000)

  output$cliquesPlot_pdf <- plotDownloadPDF(function() {
    req(rv$cliques_result, input$cliqueSelect)
    if (input$cliqueSelect == "") return()
    plot(rv$cliques_result, first = as.integer(input$cliqueSelect), n = 1, ask = FALSE,
      cut = input$cutClique, minimum = input$minimumClique, label.cex = input$node.labelClique,
      edge.label.cex = input$edge.labelClique, vsize = input$vsizeClique, layout = input$layoutClique, mar = DEFAULT_MAR)
  }, "cliques_plot", 10, 8)

  # Comparison Plot
  output$comparisonPlot_png <- plotDownloadPNG(function() {
    req(rv$data, input$type, input$compareSelect, input$group1, input$group2)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    if (input$compare_sig) {
      permtest <- permutation_test(group_tnad[[input$group1]], group_tnad[[input$group2]],
        iter = input$iterPerm, paired = input$pairedPerm, level = input$levelPerm)
      plot(permtest, cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup, mar = DEFAULT_MAR)
    } else {
      plot_compare(group_tnad[[input$group1]], group_tnad[[input$group2]],
        cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup,
        posCol = "darkblue", negCol = "red", mar = DEFAULT_MAR)
    }
  }, "comparison_plot", 1200, 1000)

  output$comparisonPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data, input$type, input$compareSelect, input$group1, input$group2)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    if (input$compare_sig) {
      permtest <- permutation_test(group_tnad[[input$group1]], group_tnad[[input$group2]],
        iter = input$iterPerm, paired = input$pairedPerm, level = input$levelPerm)
      plot(permtest, cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup, mar = DEFAULT_MAR)
    } else {
      plot_compare(group_tnad[[input$group1]], group_tnad[[input$group2]],
        cut = input$cutGroup, minimum = input$minimumGroup, label.cex = input$node.labelGroup,
        edge.label.cex = input$edge.labelGroup, vsize = input$vsizeGroup, layout = input$layoutGroup,
        posCol = "darkblue", negCol = "red", mar = DEFAULT_MAR)
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
    plot(centralities(group_tnad, measures = input$centralitiesChoiceGroup,
      normalize = input$normalizeGroup, loops = input$loopsGroup), ncol = input$nColsCentralitiesGroup)
  }, "group_centralities", 1600, 1200)

  output$groupCentralitiesPlot_pdf <- plotDownloadPDF(function() {
    req(rv$data, rv$tna_result, input$type, input$compareSelect)
    group_tnad <- group_model(rv$data, type = input$type, group = input$compareSelect)
    plot(centralities(group_tnad, measures = input$centralitiesChoiceGroup,
      normalize = input$normalizeGroup, loops = input$loopsGroup), ncol = input$nColsCentralitiesGroup)
  }, "group_centralities", 12, 10)

  # Bootstrap Plot
  output$tnaPlotBoot_png <- plotDownloadPNG(function() {
    req(rv$bootstrap_result)
    plot(rv$bootstrap_result, cut = input$cutBoot, minimum = input$minimumBoot,
      label.cex = input$node.labelBoot, edge.label.cex = input$edge.labelBoot,
      vsize = input$vsizeBoot, layout = input$layoutBoot, mar = DEFAULT_MAR)
  }, "bootstrap_validation", 1200, 1000)

  output$tnaPlotBoot_pdf <- plotDownloadPDF(function() {
    req(rv$bootstrap_result)
    plot(rv$bootstrap_result, cut = input$cutBoot, minimum = input$minimumBoot,
      label.cex = input$node.labelBoot, edge.label.cex = input$edge.labelBoot,
      vsize = input$vsizeBoot, layout = input$layoutBoot, mar = DEFAULT_MAR)
  }, "bootstrap_validation", 10, 8)
}

# ============================================================================
# Run Application
# ============================================================================

shinyApp(ui = ui, server = server)
