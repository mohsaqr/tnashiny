# Changelog

## [2.0.1] - 2026-01-18

### Added
- **Export Functionality**: Added export buttons for all tables and plots
  - Tables can be exported as CSV or Excel (.xlsx)
  - Plots can be exported as PNG or PDF
  - Export buttons appear next to each table/plot section
  - New module: `R/mod_export.R` with helper functions

- **Session Persistence**: User sessions now persist across browser refreshes
  - Authentication state stored in browser localStorage
  - Automatic session restoration on page load
  - Drive folder IDs preserved between sessions

- **Open TNA Folder**: "Open TNA Folder" link in user menu now opens the user's specific TNA_App folder in Google Drive

### Changed
- **UI Styling**: Enhanced visual appearance
  - Improved toolbar styling with gradient backgrounds
  - Better button styling with hover effects
  - Polished sidebar and box components
  - Export button styling with color-coded hover states

### Fixed
- **JavaScript Error Handling**: Added try-catch blocks to all localStorage operations to prevent JavaScript errors from breaking the app
- **Session Restoration**: Corrupted localStorage data is now automatically cleared
- **Main UI Error Handling**: Added error boundary for main UI rendering with fallback error page
- **Dashboard Header**: Made logo modification code safer with structure validation
- **Drive Upload**: Fixed "Unrecognized type" error by removing explicit type parameter

### Technical Details

#### New Files
- `R/mod_export.R` - Export helper functions:
  - `tableExportButtons()` - Creates CSV/Excel export buttons
  - `plotExportButtons()` - Creates PNG/PDF export buttons
  - `tableDownloadCSV()` / `tableDownloadXLSX()` - Download handlers for tables
  - `plotDownloadPNG()` / `plotDownloadPDF()` - Download handlers for plots
  - `generatePDFReport()` - PDF report generation
  - `exportAllTablesToExcel()` - Multi-sheet Excel export
  - `exportAllPlotsToPDF()` - Multi-page PDF export

#### Modified Files
- `app.R` - Main application:
  - Added localStorage JavaScript for session persistence
  - Added export buttons to all tabs (Results, Visualization, Centrality, etc.)
  - Added download handlers for all exports
  - Added error handling for UI rendering
  - Made header logo modification safer

- `www/custom.css` - Styling:
  - Added `.export-btn-group` styles
  - Added `.btn-export` button styles with hover effects
  - Added `.box-header-with-export` flex layout
  - Added `.content-toolbar` styling

- `R/mod_drive.R` - Drive operations:
  - Fixed `drive_upload` to auto-detect file type

- `R/mod_auth.R` - Authentication:
  - Improved token configuration with refresh token support

### Dependencies
No new dependencies added. Uses existing packages:
- `rio` for Excel export
- `rmarkdown` for PDF report generation (optional)
