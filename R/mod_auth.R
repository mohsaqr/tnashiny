# ============================================================================
# Authentication Module - Google OAuth
# ============================================================================
# Handles Google Sign-In, session management, and logout
# ============================================================================

# Ensure %||% is available
if (!exists("%||%")) {
  `%||%` <- function(x, y) if (is.null(x) || length(x) == 0 || (is.character(x) && x == "")) y else x
}

#' Authentication Module UI
#' @param id Module namespace ID
authModuleUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Include shinyjs
    useShinyjs(),

    # Hidden div to store auth state
    hidden(
      div(id = ns("auth_state"), "")
    )
  )
}

#' Login Page UI
#' @param id Module namespace ID
loginPageUI <- function(id) {
  ns <- NS(id)

  div(
    class = "login-container",
    div(
      class = "login-box",
      # Logo and title
      div(
        class = "login-header",
        img(src = "logo.png", height = "80", width = "73", alt = "TNA Logo"),
        h1("Transition Network Analysis"),
        p(class = "login-subtitle", "Analyze transition networks with ease")
      ),

      # Features list
      div(
        class = "login-features",
        div(class = "feature-item", icon("chart-bar"), span("Comprehensive Analysis")),
        div(class = "feature-item", icon("circle-nodes"), span("Network Visualization")),
        div(class = "feature-item", icon("cloud"), span("Cloud Storage"))
      ),

      # Privacy note
      div(
        class = "privacy-note",
        icon("shield-halved"),
        p("Your data stays in YOUR Google Drive. We store nothing.")
      ),

      # Google Sign-In Button
      div(
        class = "login-button-container",
        actionButton(
          ns("google_signin"),
          label = tagList(
            tags$img(
              src = "https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg",
              height = "20",
              style = "margin-right: 10px;"
            ),
            "Sign in with Google"
          ),
          class = "btn-google-signin"
        )
      ),

      # Footer
      div(
        class = "login-footer",
        p(
          "By signing in, you agree to allow TNA to create files in your Google Drive.",
          br(),
          tags$a(href = "https://sonsoles.me/tna", target = "_blank", "Learn more about TNA")
        )
      )
    )
  )
}

#' Authentication Module Server
#' @param id Module namespace ID
#' @param parent_session The parent session for reactiveValues access
authModuleServer <- function(id, parent_session = NULL) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Reactive values for auth state
    auth <- reactiveValues(
      logged_in = FALSE,
      user_email = NULL,
      user_name = NULL,
      user_picture = NULL,
      access_token = NULL,
      token_expiry = NULL
    )

    # Check for existing token on app start
    observe({
      # Check URL parameters for OAuth callback
      query <- parseQueryString(session$clientData$url_search)

      if (!is.null(query$code)) {
        # We have an authorization code - exchange for token
        tryCatch({
          token <- exchange_code_for_token(query$code, session)
          if (!is.null(token)) {
            # Get user info
            user_info <- get_user_info(token$access_token)
            if (!is.null(user_info)) {
              auth$logged_in <- TRUE
              auth$user_email <- user_info$email
              auth$user_name <- user_info$name
              auth$user_picture <- user_info$picture
              auth$access_token <- token$access_token
              auth$token_expiry <- Sys.time() + token$expires_in

              # Configure googledrive with the token
              configure_drive_token(token$access_token)

              # Clear the URL parameters
              updateQueryString("?", mode = "replace", session = session)

              showNotification(
                paste("Welcome,", user_info$name),
                type = "message",
                duration = 3
              )
            }
          }
        }, error = function(e) {
          showNotification(
            paste("Authentication failed:", e$message),
            type = "error",
            duration = 5
          )
        })
      }
    }) |> bindEvent(session$clientData$url_search, once = TRUE)

    # Handle Google Sign-In click
    observeEvent(input$google_signin, {
      # Build OAuth URL
      auth_url <- build_auth_url(session)

      # Redirect to Google
      runjs(sprintf('window.location.href = "%s";', auth_url))
    })

    # Return auth state
    return(auth)
  })
}

#' Build Google OAuth Authorization URL
#' @param session Shiny session
build_auth_url <- function(session) {
  # Get the current URL for redirect
  redirect_uri <- get_redirect_uri(session)
  state <- generate_state_token()

  # Build authorization URL manually
  base_url <- "https://accounts.google.com/o/oauth2/v2/auth"

  params <- list(
    client_id = GOOGLE_CLIENT_ID,
    redirect_uri = redirect_uri,
    response_type = "code",
    scope = paste(GOOGLE_SCOPES, collapse = " "),
    state = state,
    access_type = "offline",
    prompt = "consent"
  )

  # Build query string
  query_string <- paste(
    sapply(names(params), function(name) {
      paste0(name, "=", utils::URLencode(as.character(params[[name]]), reserved = TRUE))
    }),
    collapse = "&"
  )

  auth_url <- paste0(base_url, "?", query_string)

  message("Built auth URL: ", substr(auth_url, 1, 100), "...")
  message("Redirect URI: ", redirect_uri)

  return(auth_url)
}

#' Get redirect URI based on current session
#' @param session Shiny session
get_redirect_uri <- function(session) {
  # Use fixed redirect URI for local development (must match Google Console)
  # This avoids redirect_uri_mismatch errors from dynamic ports
  redirect_uri <- "http://localhost:3838/"

  message("Generated redirect URI: ", redirect_uri)
  return(redirect_uri)
}

#' Generate state token for CSRF protection
generate_state_token <- function() {
  paste0(sample(c(letters, LETTERS, 0:9), 32, replace = TRUE), collapse = "")
}

#' Exchange authorization code for access token
#' @param code Authorization code from OAuth callback
#' @param session Shiny session
exchange_code_for_token <- function(code, session) {
  redirect_uri <- get_redirect_uri(session)

  message("=== OAuth Token Exchange ===")
  message("Redirect URI: ", redirect_uri)
  message("Client ID: ", substr(GOOGLE_CLIENT_ID, 1, 20), "...")
  message("Client Secret present: ", nchar(GOOGLE_CLIENT_SECRET) > 0)

  response <- httr::POST(
    "https://oauth2.googleapis.com/token",
    body = list(
      code = code,
      client_id = GOOGLE_CLIENT_ID,
      client_secret = GOOGLE_CLIENT_SECRET,
      redirect_uri = redirect_uri,
      grant_type = "authorization_code"
    ),
    encode = "form"
  )

  status <- httr::status_code(response)
  message("Token exchange response status: ", status)

  if (status == 200) {
    content <- httr::content(response, as = "parsed")
    message("Token exchange successful!")
    return(content)
  } else {
    error_content <- httr::content(response, as = "parsed")
    error_msg <- error_content$error_description %||% error_content$error %||% "Unknown error"
    message("Token exchange failed: ", error_msg)
    stop(paste("Token exchange failed:", error_msg))
  }
}

#' Get user info from Google
#' @param access_token OAuth access token
get_user_info <- function(access_token) {
  response <- httr::GET(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    httr::add_headers(Authorization = paste("Bearer", access_token))
  )

  if (httr::status_code(response) == 200) {
    return(httr::content(response, as = "parsed"))
  }

  return(NULL)
}

#' Configure googledrive package with access token
#' @param access_token OAuth access token
#' @param refresh_token Optional refresh token
configure_drive_token <- function(access_token, refresh_token = NULL) {
  message("=== CONFIGURING DRIVE TOKEN ===")

  tryCatch({
    # Create credentials list that gargle expects
    creds <- list(
      access_token = access_token,
      token_type = "Bearer",
      expires_in = 3600
    )

    # Add refresh token if available
    if (!is.null(refresh_token)) {
      creds$refresh_token <- refresh_token
    }

    # Create httr token object
    token <- httr::Token2.0$new(
      app = httr::oauth_app(
        appname = "tna-app",
        key = GOOGLE_CLIENT_ID,
        secret = GOOGLE_CLIENT_SECRET
      ),
      endpoint = httr::oauth_endpoints("google"),
      credentials = creds,
      params = list(
        scope = paste(GOOGLE_SCOPES, collapse = " "),
        type = NULL,
        use_oob = FALSE,
        as_header = TRUE
      ),
      cache_path = FALSE
    )

    message("Token object created, configuring googledrive...")

    # Configure googledrive with the token
    googledrive::drive_auth(token = token)

    message("googledrive configured successfully")

    # Verify it worked by trying a simple operation
    tryCatch({
      googledrive::drive_user()
      message("Drive user verification: SUCCESS")
    }, error = function(e) {
      message("Drive user verification failed: ", e$message)
    })

    return(TRUE)

  }, error = function(e) {
    message("Error configuring drive token: ", e$message)
    return(FALSE)
  })
}

#' Logout function - clear auth state
#' @param auth Reactive auth object
logout_user <- function(auth) {
  auth$logged_in <- FALSE
  auth$user_email <- NULL
  auth$user_name <- NULL
  auth$user_picture <- NULL
  auth$access_token <- NULL
  auth$token_expiry <- NULL

  # Deauthorize googledrive
  tryCatch({
    googledrive::drive_deauth()
  }, error = function(e) {
    # Ignore errors during deauth
  })
}
