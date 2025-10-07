
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_socketio import SocketIO, send
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Optional
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import os




import eventlet
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Uploads config
# Profile picture upload folder
app.config['PROFILE_PIC_UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'profile_pics')
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet')

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    profile_pic = db.Column(db.String(120), nullable=True, default='default.png')
    # Friend relationships
    friends = db.relationship('Friend', foreign_keys='Friend.user_id', backref='user', lazy='dynamic')
    friend_of = db.relationship('Friend', foreign_keys='Friend.friend_id', backref='friend', lazy='dynamic')
    # Group memberships
    groups = db.relationship('GroupMember', backref='user', lazy='dynamic')
# Friend model
class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    accepted = db.Column(db.Boolean, default=False)

# Group model
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    # Add more fields as needed

# Group membership
class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    group = db.relationship('Group', backref='members')
class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    read = db.Column(db.Boolean, default=False)
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

# Group chat message model
class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User')
    group = db.relationship('Group')
# Private chat route
@app.route('/chat/<int:friend_id>', methods=['GET', 'POST'])
@login_required
def private_chat(friend_id):
    friend = User.query.get_or_404(friend_id)
    # Check if they are friends
    is_friend = Friend.query.filter_by(user_id=current_user.id, friend_id=friend_id, accepted=True).first() is not None
    if not is_friend:
        flash('You can only chat with your friends.', 'danger')
        return redirect(url_for('friends'))
    if request.method == 'POST':
        msg = request.form.get('message')
        if msg:
            db.session.add(PrivateMessage(sender_id=current_user.id, receiver_id=friend_id, content=msg, read=False))
            db.session.commit()
    # Mark all messages sent to current user as read
    unread = PrivateMessage.query.filter_by(sender_id=friend_id, receiver_id=current_user.id, read=False).all()
    for m in unread:
        m.read = True
    if unread:
        db.session.commit()
    # Show messages between current user and friend
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == friend_id)) |
        ((PrivateMessage.sender_id == friend_id) & (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()
    return render_template('private_chat.html', friend=friend, messages=messages, is_friend=is_friend, user=current_user)

# API endpoint for polling messages (returns JSON)
@app.route('/chat/<int:friend_id>/messages')
@login_required
def private_chat_messages(friend_id):
    friend = User.query.get_or_404(friend_id)
    is_friend = Friend.query.filter_by(user_id=current_user.id, friend_id=friend_id, accepted=True).first() is not None
    if not is_friend:
        return {"messages": []}
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == friend_id)) |
        ((PrivateMessage.sender_id == friend_id) & (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()
    return {"messages": [
        {"sender": m.sender.username, "content": m.content, "timestamp": m.timestamp.strftime('%Y-%m-%d %H:%M:%S')} for m in messages
    ]}

# API endpoint for message count (for notification)
@app.route('/chat/<int:friend_id>/messages/count')
@login_required
def private_chat_message_count(friend_id):
    friend = User.query.get_or_404(friend_id)
    is_friend = Friend.query.filter_by(user_id=current_user.id, friend_id=friend_id, accepted=True).first() is not None
    if not is_friend:
        return {"count": 0}
    count = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == friend_id)) |
        ((PrivateMessage.sender_id == friend_id) & (PrivateMessage.receiver_id == current_user.id))
    ).count()
    return {"count": count}

# Friends page
@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        if action == 'add':
            # Send friend request
            if not Friend.query.filter_by(user_id=current_user.id, friend_id=user_id).first():
                db.session.add(Friend(user_id=current_user.id, friend_id=user_id, accepted=False))
                db.session.commit()
        elif action == 'accept':
            # Accept friend request
            fr = Friend.query.filter_by(user_id=user_id, friend_id=current_user.id, accepted=False).first()
            if fr:
                fr.accepted = True
                # Add reciprocal friendship
                db.session.add(Friend(user_id=current_user.id, friend_id=user_id, accepted=True))
                db.session.commit()
        elif action == 'remove':
            # Remove friend
            Friend.query.filter_by(user_id=current_user.id, friend_id=user_id).delete()
            Friend.query.filter_by(user_id=user_id, friend_id=current_user.id).delete()
            db.session.commit()
    # Friends who accepted
    accepted = Friend.query.filter_by(user_id=current_user.id, accepted=True).all()
    # Pending requests sent by user
    pending = Friend.query.filter_by(user_id=current_user.id, accepted=False).all()
    # Requests received
    received = Friend.query.filter_by(friend_id=current_user.id, accepted=False).all()
    # All users except self and already friends/pending
    exclude_ids = [current_user.id] + [f.friend_id for f in accepted+pending] + [f.user_id for f in received]
    others = User.query.filter(~User.id.in_(exclude_ids)).all()
    return render_template('friends.html', accepted=accepted, pending=pending, received=received, others=others, user=current_user)

# Groups page
@app.route('/groups', methods=['GET', 'POST'])
@login_required
def groups():
    if request.method == 'POST':
        action = request.form.get('action')
        group_id = request.form.get('group_id')
        if action == 'join':
            if not GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first():
                db.session.add(GroupMember(user_id=current_user.id, group_id=group_id))
                db.session.commit()
        elif action == 'leave':
            GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).delete()
            db.session.commit()
    all_groups = Group.query.all()
    user_groups = [gm.group for gm in current_user.groups]
    return render_template('groups.html', all_groups=all_groups, user_groups=user_groups)

# Settings page
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)



# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration form
# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

# Login form
# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Profile edit form
class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[Optional(), Length(min=3, max=80)])
    password = PasswordField('New Password', validators=[Optional(), Length(min=4)])
    confirm_password = PasswordField('Confirm Password', validators=[Optional(), EqualTo('password')])
    profile_pic = FileField('Profile Picture (jpg, png)')
    submit = SubmitField('Update Profile')
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        # Update username
        if form.username.data and form.username.data != current_user.username:
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken.', 'danger')
                return redirect(url_for('profile'))
            current_user.username = form.username.data
        # Update password
        if form.password.data:
            current_user.password = form.password.data
        # Update profile picture
        if form.profile_pic.data:
            pic_file = form.profile_pic.data
            filename = f"user_{current_user.id}_" + secure_filename(pic_file.filename)
            filepath = os.path.join(app.config['PROFILE_PIC_UPLOAD_FOLDER'], filename)
            pic_file.save(filepath)
            current_user.profile_pic = filename
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form, user=current_user)


@app.route('/')
@login_required
def home():
    return render_template('index.html', username=current_user.username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



# Create group route
@app.route('/groups/create', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name')
        if name and not Group.query.filter_by(name=name).first():
            group = Group(name=name)
            db.session.add(group)
            db.session.commit()
            db.session.add(GroupMember(user_id=current_user.id, group_id=group.id))
            db.session.commit()
            flash('Group created and joined!', 'success')
            return redirect(url_for('groups'))
        else:
            flash('Group name is required or already exists.', 'danger')
    return render_template('create_group.html')

# Group chat route
@app.route('/groups/<int:group_id>/chat', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first() is not None
    if not is_member:
        flash('You must join the group to chat.', 'danger')
        return redirect(url_for('groups'))
    if request.method == 'POST':
        msg = request.form.get('message')
        if msg:
            db.session.add(GroupMessage(group_id=group_id, user_id=current_user.id, content=msg))
            db.session.commit()
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp.asc()).all()
    return render_template('group_chat.html', group=group, messages=messages)

# UI messages endpoint
@app.route('/chatui/<int:friend_id>/messages')
@login_required
def chat_ui_messages(friend_id):
    friend = User.query.get_or_404(friend_id)
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == friend_id)) |
        ((PrivateMessage.sender_id == friend_id) & (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()
    history = []
    for m in messages:
        is_me = m.sender_id == current_user.id
        history.append({
            "user": current_user.username if is_me else friend.username,
            "text": m.content,
            "time": m.timestamp.strftime('%H:%M'),
            "read": m.read if is_me else None,
            "profile_pic": (current_user.profile_pic if is_me else friend.profile_pic)
        })
    return {"history": history}

# --- SOCKET.IO EVENTS FOR REAL-TIME CHAT ---
from flask_socketio import emit, join_room, leave_room

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    import datetime
    room = data['room']
    message = data['message']
    sender = data['sender']
    # Parse friend_id from room name: chat_<user1>_<user2>
    try:
        parts = room.split('_')
        # Find the friend id (not current user)
        user_ids = [int(x) for x in parts[1:3] if x.isdigit()]
        friend_id = [uid for uid in user_ids if uid != current_user.id][0]
    except Exception:
        friend_id = None
    # Save message to DB
    msg = PrivateMessage(sender_id=current_user.id, receiver_id=friend_id, content=message, read=False)
    db.session.add(msg)
    db.session.commit()
    # Format timestamp
    now = datetime.datetime.now().strftime('%H:%M')
    emit('receive_message', {
        'user': sender,
        'text': message,
        'profile_pic': current_user.profile_pic,
        'time': now,
        'read': False
    }, room=room)
    # Optionally, emit to receiver to update unread count/notification

@socketio.on('typing')
def handle_typing(data):
    room = data['room']
    sender = data['sender']
    emit('user_typing', {'user': sender}, room=room, include_self=False)

# Real-time read receipt update
@socketio.on('mark_read')
def handle_mark_read(data):
    room = data['room']
    friend_id = data.get('friend_id')
    # Mark all messages from friend to current user as read
    unread = PrivateMessage.query.filter_by(sender_id=friend_id, receiver_id=current_user.id, read=False).all()
    for m in unread:
        m.read = True
    if unread:
        db.session.commit()
    # Notify both users in the room
    emit('read_receipt', {'reader': current_user.username}, room=room)

@socketio.on('notify')
def handle_notify(data):
    room = data['room']
    notification = data['notification']
    emit('notification', {'notification': notification}, room=room)

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    print(' * Running with eventlet for real-time WebSocket support')
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
