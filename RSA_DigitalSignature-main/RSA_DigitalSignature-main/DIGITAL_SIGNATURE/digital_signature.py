from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = 'your_secret_key_very_secret_and_long' # Nên đặt một khóa bí mật mạnh, duy nhất
app.config['SECRET_KEY'] = 'another_secret_key_for_socketio' # Khóa bí mật cho SocketIO
socketio = SocketIO(app) # Khởi tạo SocketIO

UPLOAD_FOLDER = 'signed_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

PRIVATE_KEY_PATH = os.path.join(UPLOAD_FOLDER, 'private.pem')
PUBLIC_KEY_PATH = os.path.join(UPLOAD_FOLDER, 'public.pem')

# Tên phòng chat mặc định (có thể làm động sau này)
CHAT_ROOM_NAME = 'general_chat_room'

@app.route('/', methods=['GET', 'POST'])
def index():
    signature_filename = None
    signed_file_filename = None
    verify_result = None

    verify_uploaded_filename = None
    verify_uploaded_sig_filename = None
    separate_verify_result = None

    key_generated = os.path.exists(PUBLIC_KEY_PATH)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate_keys':
            key = RSA.generate(2048)
            with open(PRIVATE_KEY_PATH, 'wb') as f:
                f.write(key.export_key())
            with open(PUBLIC_KEY_PATH, 'wb') as f:
                f.write(key.publickey().export_key())
            flash('Đã tạo khóa RSA thành công!', 'success')
            return redirect(url_for('index'))

        elif action == 'upload_and_sign':
            file = request.files.get('file')
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)

                with open(file_path, 'rb') as f:
                    data = f.read()

                try:
                    if not os.path.exists(PRIVATE_KEY_PATH):
                        flash('Chưa có khóa riêng tư. Vui lòng tạo khóa trước.', 'danger')
                        return render_template(
                            'index.html',
                            key_generated=key_generated,
                            signed_file_path=signed_file_filename,
                            signature_path=signature_filename,
                            verify_result=verify_result,
                            verify_uploaded_filename=verify_uploaded_filename,
                            verify_uploaded_sig_filename=verify_uploaded_sig_filename,
                            separate_verify_result=separate_verify_result
                        )

                    private_key = RSA.import_key(open(PRIVATE_KEY_PATH, 'rb').read())
                    h = SHA256.new(data)
                    signature = pkcs1_15.new(private_key).sign(h)

                    sig_filename = filename + '.sig'
                    sig_path = os.path.join(UPLOAD_FOLDER, sig_filename)
                    with open(sig_path, 'wb') as sig_file:
                        sig_file.write(signature)

                    flash('File đã được ký thành công!', 'success')
                    signed_file_filename = filename
                    signature_filename = sig_filename

                    if not os.path.exists(PUBLIC_KEY_PATH):
                        verify_result = '❌ Không tìm thấy khóa công khai để kiểm tra chữ ký.'
                    else:
                        public_key = RSA.import_key(open(PUBLIC_KEY_PATH, 'rb').read())
                        try:
                            pkcs1_15.new(public_key).verify(h, signature)
                            verify_result = '✅ Chữ ký hợp lệ.'
                        except (ValueError, TypeError):
                            verify_result = '❌ Chữ ký KHÔNG hợp lệ.'

                except Exception as e:
                    flash(f'Lỗi khi ký file: {e}', 'danger')
                    signed_file_filename = None
                    signature_filename = None
                    verify_result = None
            else:
                flash('Vui lòng chọn một file để ký.', 'warning')
                signed_file_filename = None
                signature_filename = None
                verify_result = None

        elif action == 'upload_and_verify':
            original_file = request.files.get('original_file_to_verify')
            signature_file = request.files.get('signature_file_to_verify')

            if not original_file or original_file.filename == '':
                flash('Vui lòng chọn file gốc để xác minh.', 'warning')
            elif not signature_file or signature_file.filename == '':
                flash('Vui lòng chọn file chữ ký (.sig) để xác minh.', 'warning')
            else:
                original_filename = secure_filename(original_file.filename)
                signature_filename_to_verify = secure_filename(signature_file.filename)

                # Lưu thẳng vào UPLOAD_FOLDER với tên chuẩn
                original_file_path = os.path.join(UPLOAD_FOLDER, original_filename)
                signature_file_path = os.path.join(UPLOAD_FOLDER, signature_filename_to_verify)

                original_file.save(original_file_path)
                signature_file.save(signature_file_path)

                verify_uploaded_filename = original_filename
                verify_uploaded_sig_filename = signature_filename_to_verify

                try:
                    if not os.path.exists(PUBLIC_KEY_PATH):
                        separate_verify_result = '❌ Không tìm thấy khóa công khai. Vui lòng tạo khóa trước.'
                        flash('Không tìm thấy khóa công khai để xác minh.', 'danger')
                    else:
                        public_key = RSA.import_key(open(PUBLIC_KEY_PATH, 'rb').read())

                        with open(original_file_path, 'rb') as f_orig:
                            original_data = f_orig.read()
                        with open(signature_file_path, 'rb') as f_sig:
                            signature_data = f_sig.read()

                        h = SHA256.new(original_data)
                        try:
                            pkcs1_15.new(public_key).verify(h, signature_data)
                            separate_verify_result = '✅ Chữ ký hợp lệ.'
                            flash('Xác minh chữ ký thành công!', 'success')

                            file_url = url_for('download_file', filename=original_filename, _external=True)
                            sig_url = url_for('download_file', filename=signature_filename_to_verify, _external=True)

                            # Gửi thông tin file và chữ ký qua SocketIO đến tất cả các client trong phòng chat
                            # Sự kiện này sẽ kích hoạt việc thêm file vào khung đính kèm trên client
                            socketio.emit('file_shared', {
                                'original_file_name': original_filename,
                                'original_file_url': file_url,
                                'signature_file_name': signature_filename_to_verify,
                                'signature_file_url': sig_url,
                                'message': f'Đã xác minh và file {original_filename} và chữ ký {signature_filename_to_verify} sẵn sàng để chia sẻ trong chat.'
                            }, room=CHAT_ROOM_NAME)

                            # Chuyển hướng trình duyệt hiện tại sang trang chat
                            return redirect(url_for('chat'))

                        except (ValueError, TypeError):
                            separate_verify_result = '❌ Chữ ký KHÔNG hợp lệ.'
                            flash('Xác minh chữ ký THẤT BẠI!', 'danger')
                except Exception as e:
                    separate_verify_result = f'❌ Lỗi trong quá trình xác minh: {e}'
                    flash(f'Lỗi trong quá trình xác minh: {e}', 'danger')
                finally:
                    # Các file đã được lưu với tên gốc, không cần xóa file temp nữa
                    pass


    return render_template(
        'index.html',
        key_generated=key_generated,
        signed_file_path=signed_file_filename,
        signature_path=signature_filename,
        verify_result=verify_result,
        verify_uploaded_filename=verify_uploaded_filename,
        verify_uploaded_sig_filename=verify_uploaded_sig_filename,
        separate_verify_result=separate_verify_result
    )

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


# --- ROUTE VÀ XỬ LÝ SOCKETIO CHO CHAT ---

@app.route('/chat')
def chat():
    return render_template('chat.html')

@socketio.on('connect')
def test_connect():
    print('Client connected:', request.sid)
    join_room(CHAT_ROOM_NAME)
    emit('message', {'msg': 'Bạn đã tham gia phòng chat.', 'sender': 'Hệ thống'}, room=request.sid)
    print(f'Client {request.sid} joined room {CHAT_ROOM_NAME}')

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected:', request.sid)
    leave_room(CHAT_ROOM_NAME)

@socketio.on('send_message')
def handle_message(data):
    message = data['message']
    sender = data.get('sender', 'Người dùng ẩn danh') # Lấy tên người gửi nếu có
    files = data.get('files', []) # Lấy danh sách file đính kèm nếu có

    print(f'Message from {sender}: {message}')
    if files:
        print(f'Attached files: {files}')

    # Gửi tin nhắn và thông tin file đến tất cả mọi người trong phòng
    emit('message', {'msg': message, 'sender': sender, 'files': files}, room=CHAT_ROOM_NAME)


if __name__ == '__main__':
    # Chạy ứng dụng với SocketIO
    socketio.run(app, debug=True, port=5000)