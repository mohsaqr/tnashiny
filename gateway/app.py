import os
import json
from flask import Flask, render_template, redirect, url_for, session, request, flash
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload # Added in subtask 5, but good to have
import io # Added in subtask 5, good to have

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_very_secret_flask_key_dev_only")

CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), 'client_secret.json')

if not os.path.exists(CLIENT_SECRETS_FILE):
    placeholder_secret = {
        "web": {
            "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
            "project_id": "YOUR_PROJECT_ID",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": "YOUR_CLIENT_SECRET",
            "redirect_uris": [
                "http://localhost:5001/oauth2callback",
                "http://127.0.0.1:5001/oauth2callback"
            ]
        }
    }
    with open(CLIENT_SECRETS_FILE, 'w') as f:
        json.dump(placeholder_secret, f)
    print(f"Placeholder {CLIENT_SECRETS_FILE} created. Replace with your actual credentials.")

SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.file'
]
REDIRECT_URI = 'http://127.0.0.1:5001/oauth2callback'

@app.route('/')
def index():
    if 'credentials' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login/google')
def login_google():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        flash("Client secrets file not found. Please configure the application.", "error")
        return redirect(url_for('index'))
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
    except Exception as e:
        flash(f"Error loading client secrets: {e}", "error")
        print(f"Error loading client secrets: {e}")
        return redirect(url_for('index'))
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.pop('state', None)
    if state is None or state != request.args.get('state'):
        flash('Invalid state parameter.', 'error')
        return redirect(url_for('index'))
    if not os.path.exists(CLIENT_SECRETS_FILE):
        flash("Client secrets file not found during callback. Please configure the application.", "error")
        return redirect(url_for('index'))
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
    except Exception as e:
        flash(f"Error loading client secrets during callback: {e}", "error")
        print(f"Error loading client secrets during callback: {e}")
        return redirect(url_for('index'))
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        flash(f"Error fetching token: {e}", "error")
        print(f"Error fetching token: {e}")
        return redirect(url_for('index'))
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    try:
        creds_obj = Credentials(**session['credentials'])
        service = build('oauth2', 'v2', credentials=creds_obj)
        user_info = service.userinfo().get().execute()
        session['user_email'] = user_info.get('email')
        session['user_name'] = user_info.get('name')
    except Exception as e:
        flash(f"Error fetching user info: {e}", "warning")
        print(f"Error fetching user info: {e}")
    flash('Successfully logged in!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'credentials' not in session:
        flash('You need to login first.', 'warning')
        return redirect(url_for('index'))
    user_email = session.get('user_email', 'N/A')
    user_name = session.get('user_name', 'N/A')
    return render_template('dashboard.html', user_email=user_email, user_name=user_name)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Google Drive Integration (from subtask 5) ---
APP_DRIVE_FOLDER_NAME = "TNA_Shiny_Gateway_States"
SHARED_EXCHANGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shiny_exchange'))
TRIGGER_SAVE_FILE = 'save_request.json'
TRIGGER_LOAD_FILE = 'load_request.json'
TEMP_RDS_FOR_UPLOAD = 'temp_shiny_state_for_upload.rds'
TEMP_RDS_FOR_LOAD = 'temp_shiny_state_for_load.rds'

@app.context_processor
def inject_global_vars():
    return dict(APP_DRIVE_FOLDER_NAME=APP_DRIVE_FOLDER_NAME)

def _get_drive_service():
    if 'credentials' not in session:
        flash("Credentials not found in session. Please login.", "warning")
        return None
    try:
        creds_obj = Credentials(**session['credentials'])
        if creds_obj.expired and creds_obj.refresh_token:
            from google.auth.transport.requests import Request as GoogleAuthRequest
            creds_obj.refresh(GoogleAuthRequest())
            session['credentials'] = {
                'token': creds_obj.token, 'refresh_token': creds_obj.refresh_token,
                'token_uri': creds_obj.token_uri, 'client_id': creds_obj.client_id,
                'client_secret': creds_obj.client_secret, 'scopes': creds_obj.scopes
            }
            print("Refreshed token.")
        return build('drive', 'v3', credentials=creds_obj)
    except Exception as e:
        flash(f"Error building Drive service: {str(e)}", "error")
        print(f"Error building Drive service: {str(e)}")
        return None

def find_or_create_app_folder(service):
    if not service: return None
    try:
        response = service.files().list(
            q=f"mimeType='application/vnd.google-apps.folder' and name='{APP_DRIVE_FOLDER_NAME}' and trashed=false",
            spaces='drive', fields='files(id, name)'
        ).execute()
        folders = response.get('files', [])
        if folders: return folders[0]['id']
        folder_metadata = {'name': APP_DRIVE_FOLDER_NAME, 'mimeType': 'application/vnd.google-apps.folder'}
        folder = service.files().create(body=folder_metadata, fields='id').execute()
        flash(f"Created app folder '{APP_DRIVE_FOLDER_NAME}' in your Google Drive.", "info")
        return folder.get('id')
    except Exception as e:
        flash(f"Error finding/creating app folder: {str(e)}", "error")
        print(f"Error finding/creating app folder: {str(e)}")
        return None

@app.route('/drive/list_files')
def list_drive_files_route():
    if 'credentials' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('index'))
    service = _get_drive_service()
    if not service: return redirect(url_for('dashboard'))
    app_folder_id = find_or_create_app_folder(service)
    if not app_folder_id: return redirect(url_for('dashboard'))
    files_list = []
    try:
        query = f"'{app_folder_id}' in parents and trashed=false and (fileExtension='rds' or mimeType='application/octet-stream')"
        response = service.files().list(q=query, spaces='drive', fields='files(id, name, modifiedTime, size)', orderBy='modifiedTime desc').execute()
        files_list = response.get('files', [])
        flash(f"Found {len(files_list)} relevant state files in '{APP_DRIVE_FOLDER_NAME}'.", "info")
    except Exception as e:
        flash(f"Error listing files from Drive: {str(e)}", "error")
        print(f"Error listing files from Drive: {str(e)}")
    session['drive_files'] = files_list
    return redirect(url_for('dashboard'))

# --- Shiny App State Interaction Routes ---

@app.route('/shiny/request_save_state', methods=['POST'])
def request_save_state_route():
    if 'credentials' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('index'))

    drive_filename = request.form.get('drive_filename')
    if not drive_filename:
        flash('Please provide a filename for Google Drive.', 'error')
        return redirect(url_for('dashboard'))
    if not drive_filename.lower().endswith('.rds'):
        drive_filename += '.rds'

    service = _get_drive_service()
    if not service: return redirect(url_for('dashboard'))

    app_folder_id = find_or_create_app_folder(service)
    if not app_folder_id: return redirect(url_for('dashboard'))

    # Ensure shared exchange directory exists
    if not os.path.exists(SHARED_EXCHANGE_DIR):
        try:
            os.makedirs(SHARED_EXCHANGE_DIR)
            print(f"Created shared exchange directory: {SHARED_EXCHANGE_DIR}")
        except Exception as e:
            flash(f"Error creating shared directory {SHARED_EXCHANGE_DIR}: {str(e)}", "error")
            print(f"Error creating shared directory {SHARED_EXCHANGE_DIR}: {str(e)}")
            return redirect(url_for('dashboard'))

    local_temp_rds_path = os.path.join(SHARED_EXCHANGE_DIR, TEMP_RDS_FOR_UPLOAD)
    trigger_file_path = os.path.join(SHARED_EXCHANGE_DIR, TRIGGER_SAVE_FILE)

    # Clean up old trigger/RDS file if they exist
    if os.path.exists(trigger_file_path): os.remove(trigger_file_path)
    if os.path.exists(local_temp_rds_path): os.remove(local_temp_rds_path)

    trigger_data = {
        "action": "save",
        "local_rds_path": local_temp_rds_path, # Shiny will save its state to this path
    }
    try:
        with open(trigger_file_path, 'w') as f:
            json.dump(trigger_data, f)
        flash(f"Save request sent to Shiny app. Please wait for Shiny to process and save its state locally.", "info")
    except Exception as e:
        flash(f"Error creating save trigger file: {str(e)}", "error")
        print(f"Error creating save trigger file: {str(e)}")
        return redirect(url_for('dashboard'))

    # This is where the gateway waits for Shiny to save the file.
    # For simplicity in this subtask, we'll just inform the user.
    # A robust solution would poll for local_temp_rds_path or a completion signal.
    # Then, another action from the user or an automatic process would trigger the upload.

    # Let's add a temporary session variable to indicate we are waiting for Shiny to save.
    session['waiting_for_shiny_save'] = {
        'local_path': local_temp_rds_path,
        'drive_filename': drive_filename,
        'app_folder_id': app_folder_id
    }

    return redirect(url_for('dashboard'))


@app.route('/shiny/confirm_upload_to_drive', methods=['POST'])
def confirm_upload_to_drive_route():
    if 'credentials' not in session or 'waiting_for_shiny_save' not in session:
        flash('Invalid session or not waiting for a save. Please start the save process again.', 'warning')
        return redirect(url_for('index'))

    save_info = session.pop('waiting_for_shiny_save', None)
    if not save_info: # Should not happen if check above passed
        flash('Save information missing from session.', 'error')
        return redirect(url_for('dashboard'))

    local_temp_rds_path = save_info['local_path']
    drive_filename = save_info['drive_filename']
    app_folder_id = save_info['app_folder_id']

    trigger_file_path = os.path.join(SHARED_EXCHANGE_DIR, TRIGGER_SAVE_FILE) # Path to original trigger

    if not os.path.exists(local_temp_rds_path):
        flash(f"Shiny app state file not found at {local_temp_rds_path}. Ensure Shiny app has saved the state.", 'error')
        # Remove the trigger file if it still exists, as Shiny might have failed or not run
        if os.path.exists(trigger_file_path):
            try: os.remove(trigger_file_path)
            except Exception as e: print(f"Could not remove trigger file {trigger_file_path}: {e}")
        return redirect(url_for('dashboard'))

    service = _get_drive_service()
    if not service: return redirect(url_for('dashboard'))

    try:
        file_metadata = {'name': drive_filename, 'parents': [app_folder_id]}
        media = MediaFileUpload(local_temp_rds_path, mimetype='application/octet-stream', resumable=True)
        uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id, name').execute()
        flash(f"Shiny state '{uploaded_file.get('name')}' uploaded to Drive (ID: {uploaded_file.get('id')}).", "success")
    except Exception as e:
        flash(f"Error uploading Shiny state to Drive: {str(e)}", "error")
        print(f"Error uploading Shiny state to Drive: {str(e)}")
    finally:
        # Clean up local temp RDS file and the original trigger file
        if os.path.exists(local_temp_rds_path):
            try: os.remove(local_temp_rds_path)
            except Exception as e: print(f"Error removing temp RDS {local_temp_rds_path}: {e}")
        if os.path.exists(trigger_file_path):
            try: os.remove(trigger_file_path)
            except Exception as e: print(f"Could not remove trigger file {trigger_file_path}: {e}")

    return redirect(url_for('list_drive_files_route')) # Refresh file list


@app.route('/shiny/request_load_state/<file_id>')
def request_load_state_route(file_id):
    if 'credentials' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('index'))

    service = _get_drive_service()
    if not service: return redirect(url_for('dashboard'))

    # Ensure shared exchange directory exists
    if not os.path.exists(SHARED_EXCHANGE_DIR):
        try:
            os.makedirs(SHARED_EXCHANGE_DIR)
            print(f"Created shared exchange directory: {SHARED_EXCHANGE_DIR}")
        except Exception as e:
            flash(f"Error creating shared directory {SHARED_EXCHANGE_DIR}: {str(e)}", "error")
            print(f"Error creating shared directory {SHARED_EXCHANGE_DIR}: {str(e)}")
            return redirect(url_for('dashboard'))

    local_temp_rds_path = os.path.join(SHARED_EXCHANGE_DIR, TEMP_RDS_FOR_LOAD)
    trigger_file_path = os.path.join(SHARED_EXCHANGE_DIR, TRIGGER_LOAD_FILE)

    # Clean up old trigger/RDS file if they exist
    if os.path.exists(trigger_file_path): os.remove(trigger_file_path)
    if os.path.exists(local_temp_rds_path): os.remove(local_temp_rds_path)

    try:
        # Download the selected file from Drive to the shared local_temp_rds_path
        file_metadata = service.files().get(fileId=file_id, fields='name').execute() # Get original name for info
        drive_file_name = file_metadata.get('name', 'unknown_file.rds')

        request_dl = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_dl)
        done = False
        while not done: status, done = downloader.next_chunk()
        fh.seek(0)
        with open(local_temp_rds_path, 'wb') as f_out:
            f_out.write(fh.getvalue())
        print(f"File {drive_file_name} (ID: {file_id}) downloaded to {local_temp_rds_path} for Shiny to load.")

        # Create trigger file for Shiny
        trigger_data = {"action": "load", "local_rds_path": local_temp_rds_path}
        with open(trigger_file_path, 'w') as f_trigger:
            json.dump(trigger_data, f_trigger)

        flash(f"Load request for '{drive_file_name}' sent to Shiny app. Check Shiny window for status.", "info")
    except Exception as e:
        flash(f"Error preparing for Shiny state load (downloading or trigger): {str(e)}", "error")
        print(f"Error preparing for Shiny state load: {str(e)}")
        # Clean up partial downloads if any
        if os.path.exists(local_temp_rds_path): os.remove(local_temp_rds_path)
        if os.path.exists(trigger_file_path): os.remove(trigger_file_path)

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=True, port=5001, host='127.0.0.1')
