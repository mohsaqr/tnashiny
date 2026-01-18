# ============================================================================
# Export Module - Tables, Plots, and PDF Reports
# ============================================================================
# Provides export functionality for all tables and plots in the app
# ============================================================================

#' Create export buttons for a table
#' @param id Base ID for the buttons
#' @param label Optional label
#' @return tagList with export buttons
tableExportButtons <- function(id, label = NULL) {
  ns_csv <- paste0(id, "_csv")
  ns_xlsx <- paste0(id, "_xlsx")

  div(
    class = "export-btn-group",
    if (!is.null(label)) span(class = "export-label", label),
    downloadButton(ns_csv, label = NULL, class = "btn-export btn-export-csv",
                   icon = icon("file-csv")),
    downloadButton(ns_xlsx, label = NULL, class = "btn-export btn-export-xlsx",
                   icon = icon("file-excel"))
  )
}

#' Create export buttons for a plot
#' @param id Base ID for the buttons
#' @param label Optional label
#' @return tagList with export buttons
plotExportButtons <- function(id, label = NULL) {
  ns_png <- paste0(id, "_png")
  ns_pdf <- paste0(id, "_pdf")

  div(
    class = "export-btn-group",
    if (!is.null(label)) span(class = "export-label", label),
    downloadButton(ns_png, label = NULL, class = "btn-export btn-export-png",
                   icon = icon("image")),
    downloadButton(ns_pdf, label = NULL, class = "btn-export btn-export-pdf",
                   icon = icon("file-pdf"))
  )
}

#' Create a download handler for table export (CSV)
#' @param data_func Function that returns the data frame
#' @param filename_base Base name for the file
#' @return downloadHandler
tableDownloadCSV <- function(data_func, filename_base) {
  downloadHandler(
    filename = function() {
      paste0(filename_base, "_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
    },
    content = function(file) {
      data <- data_func()
      if (!is.null(data) && (is.data.frame(data) || is.matrix(data))) {
        write.csv(data, file, row.names = TRUE)
      }
    },
    contentType = "text/csv"
  )
}

#' Create a download handler for table export (Excel)
#' @param data_func Function that returns the data frame
#' @param filename_base Base name for the file
#' @return downloadHandler
tableDownloadXLSX <- function(data_func, filename_base) {
  downloadHandler(
    filename = function() {
      paste0(filename_base, "_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".xlsx")
    },
    content = function(file) {
      data <- data_func()
      if (!is.null(data) && (is.data.frame(data) || is.matrix(data))) {
        rio::export(as.data.frame(data), file)
      }
    },
    contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
  )
}

#' Create a download handler for plot export (PNG)
#' @param plot_func Function that creates the plot
#' @param filename_base Base name for the file
#' @param width Width in pixels
#' @param height Height in pixels
#' @return downloadHandler
plotDownloadPNG <- function(plot_func, filename_base, width = 1200, height = 1000) {
  downloadHandler(
    filename = function() {
      paste0(filename_base, "_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".png")
    },
    content = function(file) {
      png(file, width = width, height = height, res = 150)
      tryCatch({
        plot_func()
      }, finally = {
        dev.off()
      })
    },
    contentType = "image/png"
  )
}

#' Create a download handler for plot export (PDF)
#' @param plot_func Function that creates the plot
#' @param filename_base Base name for the file
#' @param width Width in inches
#' @param height Height in inches
#' @return downloadHandler
plotDownloadPDF <- function(plot_func, filename_base, width = 10, height = 8) {
  downloadHandler(
    filename = function() {
      paste0(filename_base, "_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".pdf")
    },
    content = function(file) {
      pdf(file, width = width, height = height)
      tryCatch({
        plot_func()
      }, finally = {
        dev.off()
      })
    },
    contentType = "application/pdf"
  )
}

#' Generate comprehensive PDF report
#' @param rv Reactive values containing analysis data
#' @param settings List of current settings
#' @param file Output file path
#' @return TRUE on success
generatePDFReport <- function(rv, settings, file) {
  tryCatch({
    # Create a temporary Rmd file
    temp_rmd <- tempfile(fileext = ".Rmd")
    temp_dir <- dirname(temp_rmd)

    # Build the Rmd content
    rmd_content <- buildReportRmd(rv, settings)
    writeLines(rmd_content, temp_rmd)

    # Render to PDF
    output_file <- rmarkdown::render(
      input = temp_rmd,
      output_format = rmarkdown::pdf_document(
        toc = TRUE,
        toc_depth = 2,
        number_sections = TRUE,
        fig_width = 7,
        fig_height = 5,
        fig_caption = TRUE
      ),
      output_file = file,
      quiet = TRUE,
      envir = new.env()
    )

    unlink(temp_rmd)
    return(TRUE)

  }, error = function(e) {
    message("PDF generation error: ", e$message)
    # Fallback to HTML if PDF fails
    tryCatch({
      temp_rmd <- tempfile(fileext = ".Rmd")
      rmd_content <- buildReportRmd(rv, settings)
      writeLines(rmd_content, temp_rmd)

      html_file <- tempfile(fileext = ".html")
      rmarkdown::render(
        input = temp_rmd,
        output_format = rmarkdown::html_document(toc = TRUE),
        output_file = html_file,
        quiet = TRUE
      )

      file.copy(html_file, file, overwrite = TRUE)
      unlink(temp_rmd)
      unlink(html_file)
      return(TRUE)
    }, error = function(e2) {
      message("HTML fallback also failed: ", e2$message)
      return(FALSE)
    })
  })
}

#' Build Rmarkdown content for report
#' @param rv Reactive values
#' @param settings Settings list
#' @return Character string with Rmd content
buildReportRmd <- function(rv, settings) {
  paste0('---
title: "TNA Analysis Report"
date: "', format(Sys.time(), "%B %d, %Y"), '"
output:
  pdf_document:
    toc: true
    toc_depth: 2
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = FALSE, warning = FALSE, message = FALSE, fig.width = 7, fig.height = 5)
library(tna)
```
')
}

#' Export all tables to a single Excel workbook
#' @param data_list Named list of data frames
#' @param file Output file path
exportAllTablesToExcel <- function(data_list, file) {
  tryCatch({
    # Use openxlsx if available, otherwise rio
    if (requireNamespace("openxlsx", quietly = TRUE)) {
      wb <- openxlsx::createWorkbook()

      for (name in names(data_list)) {
        data <- data_list[[name]]
        if (!is.null(data) && (is.data.frame(data) || is.matrix(data))) {
          sheet_name <- substr(gsub("[^[:alnum:] ]", "", name), 1, 31)
          openxlsx::addWorksheet(wb, sheet_name)
          openxlsx::writeData(wb, sheet_name, as.data.frame(data), rowNames = TRUE)
        }
      }

      openxlsx::saveWorkbook(wb, file, overwrite = TRUE)
    } else {
      # Fallback: export first table
      first_data <- data_list[[1]]
      if (!is.null(first_data)) {
        rio::export(as.data.frame(first_data), file)
      }
    }
    return(TRUE)
  }, error = function(e) {
    message("Excel export error: ", e$message)
    return(FALSE)
  })
}

#' Export all plots to a single PDF
#' @param plot_funcs Named list of plot functions
#' @param file Output file path
#' @param width Page width in inches
#' @param height Page height in inches
exportAllPlotsToPDF <- function(plot_funcs, file, width = 10, height = 8) {
  tryCatch({
    pdf(file, width = width, height = height)

    for (name in names(plot_funcs)) {
      plot_func <- plot_funcs[[name]]
      if (is.function(plot_func)) {
        tryCatch({
          plot_func()
          title(main = name, outer = FALSE)
        }, error = function(e) {
          plot.new()
          text(0.5, 0.5, paste("Error generating:", name))
        })
      }
    }

    dev.off()
    return(TRUE)
  }, error = function(e) {
    message("PDF export error: ", e$message)
    try(dev.off(), silent = TRUE)
    return(FALSE)
  })
}
