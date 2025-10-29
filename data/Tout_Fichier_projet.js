==============
PYTHON COMPLET
==============

<< app.py >>:  
from flask import Flask, jsonify, request, send_from_directory, render_template, redirect, url_for, g, abort, session
from werkzeug.utils import secure_filename
from search_service import search_service, _preprocess_text
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies, verify_jwt_in_request
)
import json
from sqlalchemy import func, and_
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_mail import Mail, Message as MailMessage
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from functools import wraps
import uuid, datetime, os, logging, re
from datetime import datetime,  timezone, timedelta
from pywebpush import webpush, WebPushException
from flask_babel import Babel, gettext as _, get_locale as babel_get_locale
from smtplib import SMTPAuthenticationError

# --- Configuration ---
POSTS_PER_PAGE = 8 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SECRET_KEY'] = 'a-very-secret-key-for-flask-sessions' 
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'landrydengue1@gmail.com'
app.config['MAIL_PASSWORD'] = 'qsypazfsfylmpmbr'
app.config['MAIL_DEFAULT_SENDER'] = ('Business', app.config['MAIL_USERNAME'])
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config["JWT_SECRET_KEY"] = "another-super-secret-key-for-jwt"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=365)
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config['VAPID_PUBLIC_KEY'] = 'BDrK-J24yf6rkjf2q59pItK0D1nttJ9FCgcSnaGqBXPLAt7mATz8ZPo8BIkxZ8NTU1m2RpG7cZZpWFt8oRoX1QI'
app.config['VAPID_PRIVATE_KEY'] = 'pOTSckyEIUUKXMeIDwIOcKfMQcO4w9avUCMfVMKHPnU'
app.config['VAPID_CLAIM_EMAIL'] = 'mailto:landrydengue1@gmail.com'
jwt = JWTManager(app)

# --- Configuration de Babel ---
app.config['LANGUAGES'] = ['en', 'fr']
app.config['BABEL_DEFAULT_LOCALE'] = 'fr'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

def select_locale():
    lang = session.get('language')
    if lang in app.config['LANGUAGES']:
        return lang
    return request.accept_languages.best_match(app.config['LANGUAGES']) or app.config['BABEL_DEFAULT_LOCALE']

babel = Babel(app, locale_selector=select_locale)

@app.context_processor
def inject_get_locale():
    return {'get_locale': lambda: str(babel_get_locale())}

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'pdf', 'mp3', 'wav', 'webm', 'mp4', 'mov', 'ogg', 'm4a', 'txt'}
def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Modèles de base de données ---
user_favorites = db.Table('user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True)
)
chatroom_participants = db.Table('chatroom_participants',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('chatroom_id', db.Integer, db.ForeignKey('chatroom.id'), primary_key=True)
)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stars = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    rater_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rated_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rater = db.relationship('User', foreign_keys=[rater_id], backref='ratings_given')
    rated_user = db.relationship('User', foreign_keys=[rated_user_id], backref='ratings_received')

post_locations = db.Table('post_locations',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('location_id', db.Integer, db.ForeignKey('location.id'), primary_key=True)
)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self):
        return f'<Location {self.name}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    member_since = db.Column(db.DateTime(), default=lambda: datetime.now(timezone.utc))
    preferred_language = db.Column(db.String(5), default='fr')
    location = db.Column(db.String(100), nullable=True)
    profile_photo = db.Column(db.String(255), default=None) 
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")
    favorite_posts = db.relationship('Post', secondary=user_favorites, lazy='dynamic', backref=db.backref('favorited_by', lazy=True))
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def to_dict(self):
        avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.rated_user_id == self.id).scalar() or 0
        rating_count = len(self.ratings_received)
        return {
            'id': self.id, 'username': self.username, 'email': self.email,
            'avg_rating': round(avg_rating, 1), 'rating_count': rating_count,
            'profile_photo': url_for('uploaded_file', filename=self.profile_photo) if self.profile_photo else None
        }
    
class PostImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(255), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False, index=True)

post_interests = db.Table('post_interests',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    locations = db.relationship('Location', secondary=post_locations, lazy='subquery',
                                backref=db.backref('posts', lazy=True))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    images = db.relationship('PostImage', backref='post', lazy=True, cascade="all, delete-orphan")
    is_visible = db.Column(db.Boolean, default=True, nullable=False)
    view_count = db.Column(db.Integer, default=0)
    interest_count = db.Column(db.Integer, default=0, nullable=False)
    interested_users = db.relationship('User', secondary=post_interests, lazy='dynamic',
                                       backref=db.backref('interested_posts', lazy=True))
    def to_dict(self):
        is_favorited = False
        try:
            verify_jwt_in_request(optional=True)
            user_identity = get_jwt_identity()
            if user_identity:
                user = db.session.get(User, int(user_identity))
                if user and self in user.favorite_posts:
                    is_favorited = True
        except Exception: pass
        image_urls = [url_for('uploaded_file', filename=image.file_path, _external=True) for image in self.images]
        author_photo_url = None
        if self.author and self.author.profile_photo:
            author_photo_url = url_for('uploaded_file', filename=self.author.profile_photo, _external=True)
        return { 
            'id': self.id, 'title': self.title, 'description': self.description, 'type': self.type, 
            'category': self.category, 'timestamp': self.timestamp.isoformat(), 'user_id': self.user_id, 
            'author_username': self.author.username, 'author_photo_url': author_photo_url,
            'image_urls': image_urls, 'cover_image_url': image_urls[0] if image_urls else None,
            'is_visible': self.is_visible, 'locations': [loc.name for loc in self.locations],
            'view_count': self.view_count, 'interest_count': self.interest_count, 'is_favorited': is_favorited
        }

class Chatroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    participants = db.relationship('User', secondary=chatroom_participants, backref=db.backref('chatrooms', lazy='dynamic'))
    messages = db.relationship('Message', backref='chatroom', lazy='dynamic', cascade="all, delete-orphan")
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True) # Peut être nul pour les conversations générales
    post = db.relationship('Post', backref='chatrooms')

    def to_dict(self, user_id):
        other_participant = next((p for p in self.participants if p.id != user_id), None)
        
        # --- DÉBUT DE LA MODIFICATION ---
        # On cherche si l'utilisateur a effacé ce chat
        clear_entry = UserChatroomClear.query.filter_by(user_id=user_id, chatroom_id=self.id).first() #
        cleared_ts = clear_entry.cleared_at if clear_entry else None #
        
        # On construit la requête de base pour les messages
        messages_query = self.messages
        if cleared_ts:
            # Si effacé, on ne prend que les messages APRES la date d'effacement
            messages_query = messages_query.filter(Message.timestamp > cleared_ts) #

        last_message = messages_query.order_by(Message.timestamp.desc()).first() #
        
        # On ne compte que les "non lus" APRES la date d'effacement
        unread_count_query = MessageStatus.query.join(Message).filter( #
            Message.chatroom_id == self.id, 
            MessageStatus.user_id == user_id, 
            MessageStatus.is_read == False
        )
        if cleared_ts:
            unread_count_query = unread_count_query.filter(Message.timestamp > cleared_ts) #
        
        unread_count = unread_count_query.count() #
        # --- FIN DE LA MODIFICATION ---
        
        post_info = {'id': self.post.id, 'title': self.post.title, 'cover_image_url': self.post.to_dict().get('cover_image_url')} if self.post else None #
        
        return {
            'id': self.id,
            'other_participant': other_participant.to_dict() if other_participant else None,
            'last_message': last_message.to_dict() if last_message else None, # Sera 'None' si effacé
            'unread_count': unread_count,
            'post_info': post_info,
            'has_been_cleared': clear_entry is not None  # <-- **AJOUTE CETTE LIGNEE**
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # --- MODIFICATION 3 : Statut de message robuste ---
    # Le statut est maintenant 'sent', 'delivered', ou 'read'.
    status = db.Column(db.String(20), nullable=False, default='sent')
    sender = db.relationship('User', backref='sent_messages', lazy=True)
    file_path = db.Column(db.String(255), nullable=True)
    file_type = db.Column(db.String(100), nullable=True)
    statuses = db.relationship('MessageStatus', backref='message', cascade="all, delete-orphan")
    replied_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    replied_to = db.relationship('Message', remote_side=[id], backref='replies')

    def to_dict(self):
        replied_to_data = None
        if self.replied_to:
            replied_to_data = {
                'id': self.replied_to.id,
                'content': self.replied_to.content,
                'sender_username': self.replied_to.sender.username if self.replied_to.sender else _("Utilisateur supprimé")
            }
        sender_username = self.sender.username if self.sender else _("Utilisateur supprimé")
        return {
            'id': self.id, 'chatroom_id': self.chatroom_id, 'sender_id': self.sender_id,
            'content': self.content, 
            # MODIFIÉ: Ajout de 'Z'
            'timestamp': self.timestamp.isoformat() + 'Z',
            'sender_username': sender_username,
            'file_url': url_for('uploaded_file', filename=self.file_path, _external=True) if self.file_path else None,
            'file_type': self.file_type, 'replied_to': replied_to_data,
            'status': self.status
        }

class MessageStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    user = db.relationship('User', backref='message_statuses')

class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    subscription_info = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('push_subscription', uselist=False, cascade="all, delete-orphan"))

#with app.app_context():
    #if search_service.index is None:
        #all_posts = Post.query.all()
        #search_service.build_index(all_posts)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) 
    type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(255), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship('User', backref='notifications', foreign_keys=[user_id])
    actor = db.relationship('User', foreign_keys=[actor_id])

class UserChatroomClear(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'), nullable=False, index=True)
    cleared_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    user = db.relationship('User', backref='cleared_chats')
    chatroom = db.relationship('Chatroom', backref='cleared_by_users')
    __table_args__ = (db.UniqueConstraint('user_id', 'chatroom_id', name='_user_chatroom_uc'),)

# --- Fonctions utilitaires ---
@app.before_request
def before_request():
    g.user = None
    if 'language' in session:
        from flask_babel import refresh
        refresh()

def is_password_strong(password):
    if len(password)<6:return False
    if not re.search(r"[a-z]",password):return False
    if not re.search(r"[A-Z]",password):return False
    if not re.search(r"[0-9]",password):return False
    return True

def send_confirmation_email(user_email):
    token=s.dumps(user_email,salt='email-confirm-salt')
    confirm_url=url_for('confirm_email_route',token=token,_external=True)
    html=render_template('email/activate.html',confirm_url=confirm_url)
    msg=MailMessage(_('Confirmez votre email pour Business !'),recipients=[user_email],html=html)
    mail.send(msg)

def send_password_reset_email(user_email):
    token=s.dumps(user_email,salt='password-reset-salt')
    reset_url=url_for('reset_password_page',token=token,_external=True)
    html=render_template('email/reset_password.html',reset_url=reset_url)
    msg=MailMessage(_('Réinitialisation du mot de passe'),recipients=[user_email],html=html)
    mail.send(msg)

def send_web_push(subscription_info, payload):
    try:
        webpush(
            subscription_info=json.loads(subscription_info),
            data=json.dumps(payload),
            vapid_private_key=app.config['VAPID_PRIVATE_KEY'],
            vapid_claims={ "sub": app.config['VAPID_CLAIM_EMAIL'] }
        )
    except WebPushException as ex:
        logging.error(f"Erreur d'envoi de la notification Push: {ex}")
        if ex.response and ex.response.status_code in [404, 410]:
            endpoint = ex.response.json().get('endpoint')
            if endpoint:
                PushSubscription.query.filter(PushSubscription.subscription_info.like(f'%{endpoint}%')).delete()
                db.session.commit()

def send_notification(user_id, type, message, link, actor_id=None, save_to_db=True):
    # --- DÉBUT DE LA CORRECTION (Bug 3: Notifications) ---
    
    if save_to_db:
        # On enregistre en BDD seulement si demandé
        new_notif = Notification(user_id=user_id, type=type, message=message, link=link, actor_id=actor_id)
        db.session.add(new_notif)
        db.session.commit()

        # On n'émet pour la cloche que si c'est sauvegardé
        socketio.emit('new_notification', {
            'message': message,
            'link': link
        }, to=str(user_id))

        unread_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        socketio.emit('notification_count_update', {
            'unread_count': unread_count
        }, to=str(user_id))
    
    # --- FIN DE LA CORRECTION ---

    # On envoie TOUJOURS la notification push (c'est ce qu'on veut)
    subscription = PushSubscription.query.filter_by(user_id=user_id).first()
    if subscription:
        payload = {
            'title': _('Nouvelle notification sur Business'),
            'body': message,
            'icon': '/static/images/favicon-192x192.png',
            'badge': '/static/images/logo-badge-b.png', # Utilisation de l'icône 'B'
            'data': {'url': link}
        }
        send_web_push(subscription.subscription_info, payload)

# --- JWT Handlers ---
def load_user_for_template(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request(optional=True)
            g.user = None
            user_identity = get_jwt_identity()
            if user_identity:
                user = db.session.get(User, int(user_identity))
                g.user = user
                if user and user.preferred_language:
                    session['language'] = user.preferred_language
        except Exception:
            g.user = None
        return f(*args, **kwargs)
    return decorated_function

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    response = redirect(url_for('login_page', next=request.path))
    unset_jwt_cookies(response)
    return response

# --- Routes HTML ---
@app.route('/select-language', methods=['GET', 'POST'])
def select_language():
    if request.method == 'POST':
        lang = request.form.get('language')
        if lang in app.config['LANGUAGES']:
            session['language'] = lang
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            if user_id:
                user = db.session.get(User, int(user_id))
                if user:
                    user.preferred_language = lang
                    db.session.commit()
        return redirect(url_for('index_page'))
    if 'language' in session:
        return redirect(url_for('index_page'))
    return render_template('select_language.html')

@app.route('/')
@load_user_for_template
def index_page():
    if 'language' not in session:
        return redirect(url_for('select_language'))
    latest_posts = Post.query.filter_by(is_visible=True).order_by(Post.timestamp.desc()).limit(6).all()
    return render_template('index.html', latest_posts=latest_posts)

@app.route('/login')
@load_user_for_template
def login_page(): return render_template('login.html')

@app.route('/register')
@load_user_for_template
def register_page(): return render_template('register.html')

@app.route('/posts')
@load_user_for_template
def posts_page(): return render_template('posts.html')

@app.route('/posts/<int:post_id>')
@load_user_for_template
def post_detail_page(post_id): return render_template('post_detail.html', post_id=post_id)

@app.route('/create_post')
@jwt_required()
@load_user_for_template
def create_post_page(): return render_template('create_post.html')

@app.route('/edit_post/<int:post_id>')
@jwt_required()
@load_user_for_template
def edit_post_page(post_id):
    post = db.session.get(Post, post_id)
    if not post or str(post.user_id) != get_jwt_identity(): return _("Non autorisé"), 403
    return render_template('edit_post.html', post_id=post_id)

@app.route('/my_posts')
@jwt_required()
@load_user_for_template
def my_posts_page(): return render_template('my_posts.html')

@app.route('/favorites')
@jwt_required()
@load_user_for_template
def favorites_page(): return render_template('favorites.html')

@app.route('/messages')
@jwt_required()
@load_user_for_template
def messages_page(): return render_template('messages.html')

@app.route('/confirm/<token>')
def confirm_email_route(token):
    try: email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except SignatureExpired: return '<h1>' + _("Le lien a expiré. Veuillez vous réinscrire.") + '</h1>'
    except Exception: return '<h1>' + _("Le lien est invalide.") + '</h1>'
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_confirmed:
        return redirect(url_for('login_page', message='already_confirmed'))
    else:
        user.is_confirmed = True
        db.session.commit()
        access_token = create_access_token(identity=str(user.id))
        response = redirect(url_for('set_profile_photo_page'))
        set_access_cookies(response, access_token)
        session['language'] = user.preferred_language or 'fr'
        return response

@app.route('/forgot_password')
def forgot_password_page(): return render_template('forgot_password.html')

@app.route('/reset_password/<token>')
def reset_password_page(token):
    try: email = s.loads(token, salt='password-reset-salt', max_age=900)
    except: return "<h1>" + _("Le lien de réinitialisation est invalide ou a expiré.") + "</h1>"
    return render_template('reset_password.html', token=token)

@app.route('/profile/<username>')
@load_user_for_template
def profile_page(username):
    user = User.query.filter_by(username=username).first_or_404()
    from_post_id = request.args.get('from_post', None, type=int)
    avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.rated_user_id == user.id).scalar() or 0
    rating_count = len(user.ratings_received)
    total_interest = db.session.query(func.sum(Post.interest_count)).filter(Post.user_id == user.id).scalar() or 0
    ratings = Rating.query.filter_by(rated_user_id=user.id).order_by(Rating.timestamp.desc()).all()
    user_posts = Post.query.filter_by(user_id=user.id, is_visible=True).order_by(Post.timestamp.desc()).all()
    return render_template('profile.html', profile_user=user, posts=user_posts, avg_rating=round(avg_rating, 1), rating_count=rating_count, ratings=ratings, total_interest=total_interest, from_post_id=from_post_id)

@app.route('/help')
@load_user_for_template
def help_page(): return render_template('help.html')

@app.route('/notifications')
@jwt_required()
@load_user_for_template
def notifications_page(): return render_template('notifications.html')

@app.route('/settings')
@jwt_required()
@load_user_for_template
def settings_page(): return render_template('settings.html')

@app.route('/set-profile-photo')
@jwt_required()
@load_user_for_template
def set_profile_photo_page():
    if g.user.profile_photo: return redirect(url_for('index_page'))
    return render_template('set_profile_photo.html')
    
@app.route('/uploads/<path:filename>')
def uploaded_file(filename): return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/service-worker.js')
def service_worker():
    return send_from_directory(app.static_folder, 'js/service-worker.js')

@app.route('/manifest.json')
def manifest():
    return send_from_directory(app.static_folder, 'manifest.json')

# --- Routes API ---
@app.route('/api/register', methods=['POST'])
def register_api():
    data = request.get_json()
    username, email, password, location = data.get('username'), data.get('email'), data.get('password'), data.get('location')
    if not all([username, email, password, location]): return jsonify(success=False, message=_("Missing required fields")), 400
    if not is_password_strong(password): return jsonify(success=False, message=_("Password does not meet security criteria.")), 400
    if User.query.filter_by(username=username).first(): return jsonify(success=False, message=_("This username already exists")), 409
    if User.query.filter_by(email=email).first(): return jsonify(success=False, message=_("This email address is already in use")), 409
    new_user = User(username=username, email=email, location=location)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    send_confirmation_email(new_user.email)
    return jsonify(success=True, message=_("Registration successful! Please check your email to confirm your account.")), 201
@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not all([email, password]): return jsonify(success=False, message=_("Missing required fields")), 400
    user = User.query.filter_by(email=email).first()
    if user and not user.is_confirmed: return jsonify(success=False, message=_("Your account has not been confirmed. Please check your email.")), 403
    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.id))
        response = jsonify(success=True, message=_('Login successful'))
        set_access_cookies(response, access_token)
        session['language'] = user.preferred_language or 'fr'
        return response
    return jsonify(success=False, message=_('Incorrect email address or password.')), 401

@app.route('/api/posts/<int:post_id>/favorite', methods=['POST'])
@jwt_required()
def toggle_favorite(post_id):
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    post = db.session.get(Post, post_id)
    if not post: return jsonify(success=False, message=_("Post not found")), 404
    if post in user.favorite_posts:
        user.favorite_posts.remove(post)
        db.session.commit()
        return jsonify(success=True, status="removed")
    else:
        user.favorite_posts.append(post)
        db.session.commit()
        if post.author.id != user.id:
            link = url_for('post_detail_page', post_id=post.id, _external=True)
            message = _("has added your ad '%(title)s' to favorites.", title=post.title[:20])
            send_notification(post.author.id, 'favorite', message, link, actor_id=user.id)
        return jsonify(success=True, status="added")

# DANS app.py

@app.route('/api/chat/upload', methods=['POST'])
@jwt_required()
def upload_chat_file_api():
    if 'file' not in request.files: return jsonify(success=False, message=_('No file part')), 400
    
    file = request.files['file']
    filename = secure_filename(file.filename)
    
    # --- BLOC DE CORRECTION ---
    # Si le fichier n'a pas de nom (cas des blobs audio), on lui en donne un.
    if not filename:
        # On se base sur le mimetype pour deviner l'extension.
        if file.mimetype.startswith('audio/'):
            filename = "voix.webm" # On assume webm, le format le plus courant pour l'audio du navigateur.
        else:
             return jsonify(success=False, message=_('Invalid or disallowed file')), 400
    # --- FIN DU BLOC ---

    if not allowed_file(filename): return jsonify(success=False, message=_('Invalid or disallowed file')), 400
    
    unique_filename = str(uuid.uuid4()) + '_' + filename
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
    return jsonify(success=True, file_path=unique_filename, file_type=file.mimetype)

@app.route('/api/auth_status', methods=['GET'])
@jwt_required(optional=True)
def auth_status():
    user_identity = get_jwt_identity()
    return jsonify(is_logged_in=bool(user_identity), user_id=user_identity)

@app.route('/api/user/profile-photo', methods=['POST'])
@jwt_required()
@load_user_for_template
def upload_profile_photo():
    if 'file' not in request.files:
        return jsonify(success=False, message=_('No file')), 400
    file = request.files['file']
    if file.filename == '' or file.mimetype not in ['image/jpeg', 'image/png', 'image/gif']:
        return jsonify(success=False, message=_('Invalid image')), 400
    filename = secure_filename(file.filename)
    unique_filename = f"profile_{get_jwt_identity()}_{uuid.uuid4().hex[:8]}.{filename.rsplit('.', 1)[1].lower()}"
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', unique_filename)
    file.save(full_path)
    if not os.path.exists(full_path):
        return jsonify(success=False, message=_("File save error")), 500
    user = db.session.get(User, int(get_jwt_identity()))
    if user.profile_photo:
        old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_photo)
        if os.path.exists(old_path):
            os.remove(old_path)
    user.profile_photo = f"profiles/{unique_filename}"
    db.session.commit()
    if g.user is not None and g.user.id == user.id:
        g.user = db.session.merge(g.user)
    photo_url = url_for('uploaded_file', filename=user.profile_photo, _external=True)
    return jsonify(success=True, photo_url=photo_url)

@app.route('/api/user/profile-photo', methods=['DELETE'])
@jwt_required()
def delete_profile_photo():
    user = db.session.get(User, int(get_jwt_identity()))
    if user.profile_photo:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.profile_photo))
    user.profile_photo = None
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/logout', methods=['POST'])
def logout_api():
    response = jsonify(success=True, message=_("Logout successful"))
    unset_jwt_cookies(response)
    session.pop('language', None)
    return response

@app.route('/api/posts', methods=['GET'])
@jwt_required(optional=True)
def get_posts_api():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search')
    category = request.args.get('category')
    post_type = request.args.get('type')
    sort_by = request.args.get('sort', 'newest')
    locations_filter = request.args.getlist('locations')
    base_query = Post.query.filter_by(is_visible=True)
    if search_term:
        semantic_ids = search_service.semantic_search(search_term, k=100)
        keyword_query = Post.query.with_entities(Post.id).filter(
            Post.title.ilike(f'%{search_term}%') | Post.description.ilike(f'%{search_term}%')
        )
        keyword_ids = [item[0] for item in keyword_query.all()]
        combined_ids = list(dict.fromkeys(semantic_ids + keyword_ids))
        if not combined_ids:
            return jsonify(success=True, posts=[], has_next=False)
        base_query = base_query.filter(Post.id.in_(combined_ids))
    if category: base_query = base_query.filter_by(category=category)
    if post_type: base_query = base_query.filter_by(type=post_type)
    if locations_filter:
        base_query = base_query.join(Post.locations).filter(Location.name.in_(locations_filter))
    if sort_by == 'oldest':
        query = base_query.order_by(Post.timestamp.asc())
    else:
        query = base_query.order_by(Post.timestamp.desc())
    pagination = query.paginate(page=page, per_page=POSTS_PER_PAGE, error_out=False)
    posts, has_next = pagination.items, pagination.has_next
    return jsonify(success=True, posts=[post.to_dict() for post in posts], has_next=has_next)

@app.route('/api/posts', methods=['POST'])
@jwt_required()
def create_post_api():
    data = request.get_json()
    required_fields = ['title', 'description', 'type', 'category']
    if not all(data.get(field) for field in required_fields):
        return jsonify(success=False, message=_("Missing required fields.")), 400
    location_names = list(set([loc.strip() for loc in data.get('locations', []) if loc and isinstance(loc, str)]))
    if not location_names:
        return jsonify(success=False, message=_("Location is required.")), 400
    current_user_id = get_jwt_identity()
    try:
        new_post = Post(
            title=data['title'], description=data['description'], type=data['type'], 
            category=data['category'], user_id=current_user_id
        )
        db.session.add(new_post)
        db.session.flush()
        
        for loc_name in location_names:
            location = Location.query.filter_by(name=loc_name).first()
            if location: new_post.locations.append(location)
        
        image_paths = data.get('image_paths', [])
        for path in image_paths:
            if path:
                new_image = PostImage(file_path=path, post=new_post)
                db.session.add(new_image)
        db.session.commit()

        # NOUVEAU : Logique de notification de proximité
        users_to_notify = User.query.filter(User.location.in_(location_names), User.id != int(current_user_id)).all()
        for user in users_to_notify:
            message = _("A new ad '%(title)s' has been posted in your area!", title=new_post.title[:30])
            link = url_for('post_detail_page', post_id=new_post.id, _external=True)
            send_notification(user.id, 'new_post_local', message, link, actor_id=int(current_user_id))

        db.session.refresh(new_post)
        return jsonify(success=True, message=_('Ad created successfully!'), post=new_post.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Post creation error: {str(e)} - Data: {data}")
        return jsonify(success=False, message=_('Failed to create post. Check logs.')), 500

@app.route('/api/posts/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post_api(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify(success=False, message=_("Post not found")), 404
    if str(post.user_id) != get_jwt_identity():
        return jsonify(success=False, message=_('Unauthorized')), 403
    data = request.get_json()
    post.title = data.get('title', post.title)
    post.description = data.get('description', post.description)
    post.type = data.get('type', post.type)
    post.category = data.get('category', post.category)
    location_names = data.get('locations', [])
    if location_names:
        post.locations.clear()
        for loc_name in location_names:
            location = Location.query.filter_by(name=loc_name).first()
            if location:
                post.locations.append(location)
    PostImage.query.filter_by(post_id=post.id).delete()
    image_paths = data.get('image_paths', [])
    for path in image_paths:
        if path:
            new_image = PostImage(file_path=path, post=post)
            db.session.add(new_image)
    db.session.commit()
    return jsonify(success=True, message=_('Post updated successfully'), post=post.to_dict())

@app.route('/api/posts/my_posts', methods=['GET'])
@jwt_required()
def get_my_posts_api():
    page = request.args.get('page', 1, type=int)
    user_id = get_jwt_identity()
    pagination = Post.query.filter_by(user_id=user_id).order_by(Post.timestamp.desc()).paginate(page=page, per_page=POSTS_PER_PAGE, error_out=False)
    posts, has_next = pagination.items, pagination.has_next
    return jsonify(success=True, posts=[post.to_dict() for post in posts], has_next=has_next)

@app.route('/api/posts/<int:post_id>', methods=['GET'])
@jwt_required(optional=True)
def get_post_detail_api(post_id):
    post = db.session.get(Post, post_id)
    if post:
        post.view_count += 1
        db.session.commit()
        return jsonify(success=True, post=post.to_dict())
    else:
        return jsonify(success=False, message=_("Post not found")), 404

@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post_api(post_id):
    post = db.session.get(Post, post_id)
    if not post or str(post.user_id) != get_jwt_identity(): return jsonify(success=False, message=_('Unauthorized')), 403
    db.session.delete(post); db.session.commit()
    return jsonify(success=True, message=_('Post deleted'))

@app.route('/api/posts/<int:post_id>/toggle_visibility', methods=['POST'])
@jwt_required()
def toggle_post_visibility(post_id):
    post = db.session.get(Post, post_id)
    if not post: return jsonify(success=False, message=_("Post not found")), 404
    if str(post.user_id) != get_jwt_identity(): return jsonify(success=False, message=_("Action not authorized")), 403
    post.is_visible = not post.is_visible
    db.session.commit()
    return jsonify(success=True, message=_("Visibility changed"), new_state=post.is_visible)

@app.route('/api/favorites', methods=['GET'])
@jwt_required()
def get_favorites_api():
    page = request.args.get('page', 1, type=int)
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    query = user.favorite_posts
    pagination = query.order_by(Post.timestamp.desc()).paginate(page=page, per_page=POSTS_PER_PAGE, error_out=False)
    posts = pagination.items
    has_next = pagination.has_next
    return jsonify(success=True, posts=[post.to_dict() for post in posts], has_next=has_next)

@app.route('/api/favorites/clear', methods=['POST'])
@jwt_required()
def clear_favorites_api():
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    try:
        for post in list(user.favorite_posts):
            user.favorite_posts.remove(post)
        db.session.commit()
        return jsonify(success=True, message=_("Favorites list cleared."))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur lors de la suppression des favoris pour l'user {user_id}: {e}")
        return jsonify(success=False, message=_("An error occurred.")), 500

# DANS app.py
# REMPLACE la route get_chatrooms_api (ligne 751)

@app.route('/api/chat/chatrooms', methods=['GET'])
@jwt_required()
def get_chatrooms_api():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    chatrooms = user.chatrooms.order_by(Chatroom.created_at.desc()).all() #
    
    chatrooms_data = []
    for room in chatrooms:
        room_data = room.to_dict(user_id)
        
        # --- NOUVELLE LOGIQUE DE FILTRAGE ---
        # On cache la conversation UNIQUEMENT si l'utilisateur l'a effacée
        # ET qu'il n'y a pas de nouveaux messages.
        # On ne cache PAS les nouvelles conversations (qui n'ont pas de messages mais n'ont jamais été effacées).
        if room_data['last_message'] is None and room_data['has_been_cleared']:
            # C'est une conversation effacée et vide -> on la cache.
            continue
        else:
            # C'est une conversation active OU une nouvelle conversation -> on l'affiche.
            chatrooms_data.append(room_data)
        # --- FIN DE LA NOUVELLE LOGIQUE ---

    return jsonify(success=True, chatrooms=chatrooms_data)

@app.route('/api/chat/unread_info', methods=['GET'])
@jwt_required()
def get_unread_info():
    user_id = int(get_jwt_identity())
    total_unread = db.session.query(MessageStatus).filter_by(user_id=user_id, is_read=False).count()
    return jsonify(success=True, total_unread=total_unread)

@app.route('/api/users/<int:rated_user_id>/rate', methods=['POST'])
@jwt_required()
def rate_user(rated_user_id):
    rater_id_str = get_jwt_identity()
    if not rater_id_str:
        return jsonify(success=False, message=_("Authentication required.")), 401
    rater_id = int(rater_id_str)
    data = request.get_json()
    stars = data.get('stars')
    comment = data.get('comment')
    if not stars:
        return jsonify(success=False, message=_("The rating (stars) is required.")), 400
    if rater_id == rated_user_id:
        return jsonify(success=False, message=_("You cannot rate yourself.")), 403
    existing_rating = Rating.query.filter_by(rater_id=rater_id, rated_user_id=rated_user_id).first()
    if existing_rating:
        return jsonify(success=False, message=_("You have already rated this user.")), 409
    new_rating = Rating(rater_id=rater_id, rated_user_id=rated_user_id, stars=stars, comment=comment)
    db.session.add(new_rating)
    db.session.commit()
    rater_user = db.session.get(User, rater_id)
    rated_user = db.session.get(User, rated_user_id)
    link = url_for('profile_page', username=rated_user.username, _external=True)
    message = _("left you a review!")
    send_notification(rated_user_id, 'rating', message, link, actor_id=rater_user.id)
    return jsonify(success=True, message=_("Thank you for your evaluation!"))

# DANS app.py
# DANS app.py

# DANS app.py

# DANS app.py
# REMPLACE ta fonction start_chat_api

@app.route('/api/chat/start', methods=['POST'])
@jwt_required()
def start_chat_api():
    user_id = int(get_jwt_identity())
    current_user = db.session.get(User, user_id)
    data = request.json
    participant_id = data.get('participant_id')
    post_id = data.get('post_id')

    if not participant_id or user_id == int(participant_id) or not post_id:
        return jsonify(success=False, message=_("Invalid action")), 400

    post = db.session.get(Post, int(post_id))
    # Correction : la vérification de l'auteur était inversée. 
    # Le participant_id EST l'auteur du post.
    if not post or post.user_id != int(participant_id):
        return jsonify(success=False, message=_("Invalid post or author")), 404

    # On cherche une conversation existante pour CETTE annonce précise
    chatroom = Chatroom.query.filter(
        Chatroom.post_id == post.id,
        Chatroom.participants.any(User.id == user_id),
        Chatroom.participants.any(User.id == int(participant_id))
    ).first()

    if chatroom:
        clear_entry = UserChatroomClear.query.filter_by(
            user_id=user_id, 
            chatroom_id=chatroom.id
        ).first()
        
        if clear_entry:
            db.session.delete(clear_entry)
            db.session.commit()
        # --- FIN DE LA CORRECTION ---
        
        return jsonify(success=True, chatroom_id=chatroom.id)

    # Si aucune conversation n'existe pour cette annonce, on en crée une nouvelle
    target_user = db.session.get(User, int(participant_id))
    if not target_user:
        return jsonify(success=False, message=_("User not found")), 404

    new_chatroom = Chatroom(post_id=post.id)
    new_chatroom.participants.extend([current_user, target_user])
    db.session.add(new_chatroom)
    db.session.flush() # Pour obtenir le new_chatroom.id
    
    # Logique d'intérêt
    if current_user not in post.interested_users:
        post.interested_users.append(current_user)
        post.interest_count = post.interested_users.count()
        message = _("%(username)s is interested in your ad '%(title)s'.", username=current_user.username, title=post.title[:20])
        link = url_for('messages_page', chatroom_id=new_chatroom.id, _external=True)
        send_notification(post.user_id, 'new_interest', message, link, actor_id=current_user.id)

    db.session.commit()
    return jsonify(success=True, chatroom_id=new_chatroom.id), 201
@app.route('/api/chat/chatroom/<int:chatroom_id>', methods=['DELETE'])
@jwt_required()
def delete_chatroom(chatroom_id):
    user_id = int(get_jwt_identity())
    chatroom = db.session.get(Chatroom, chatroom_id)
    
    if not chatroom or not any(p.id == user_id for p in chatroom.participants):
        return jsonify(success=False, message=_("Not found or unauthorized")), 404

    clear_entry = UserChatroomClear.query.filter_by(
        user_id=user_id, 
        chatroom_id=chatroom_id
    ).first()
    
    if clear_entry:
        # MODIFIÉ: Utilise utcnow()
        clear_entry.cleared_at = datetime.now(timezone.utc)
    else:
        new_clear_entry = UserChatroomClear(user_id=user_id, chatroom_id=chatroom_id)
        db.session.add(new_clear_entry)
    
    db.session.commit()
    message_ids_subquery = db.session.query(Message.id).filter(
        Message.chatroom_id == chatroom_id
    ).subquery()
    MessageStatus.query.filter(
        MessageStatus.user_id == user_id,
        MessageStatus.message_id.in_(message_ids_subquery)
    ).delete(synchronize_session=False)
    
    db.session.commit()
    
    return jsonify(success=True, message=_("Conversation cleared."))

@app.route('/api/request_password_reset', methods=['POST'])
def request_password_reset_api():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user: send_password_reset_email(user.email)
    return jsonify(success=True, message=_("If an account with this email exists, a reset link has been sent."))

@app.route('/api/reset_password_with_token', methods=['POST'])
def reset_password_with_token_api():
    data = request.get_json()
    token, password = data.get('token'), data.get('password')
    if not all([token, password]): return jsonify(success=False, message=_("Missing data.")), 400
    try: email = s.loads(token, salt='password-reset-salt', max_age=900)
    except: return jsonify(success=False, message=_("The link is invalid or has expired.")), 400
    if not is_password_strong(password): return jsonify(success=False, message=_("The password does not meet security criteria.")), 400
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify(success=False, message=_("User not found.")), 404
    user.set_password(password)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.timestamp.desc()).all()
    def get_actor_username(notif):
        if notif.actor: return notif.actor.username
        return _('[User deleted]')
    return jsonify(success=True, notifications=[{
        'id': n.id, 'type': n.type, 'message': n.message, 'link': n.link, 'is_read': n.is_read,
        'timestamp': n.timestamp.isoformat(), 'actor_username': get_actor_username(n)
    } for n in notifications])

@app.route('/api/notifications/unread', methods=['GET'])
@jwt_required()
def get_unread_notifications():
    user_id = get_jwt_identity()
    unread_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
    return jsonify(success=True, unread_count=unread_count)

@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
@jwt_required()
def mark_notification_read(notif_id):
    user_id = get_jwt_identity()
    notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
    if notif:
        notif.is_read = True
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False, message=_('Notification not found')), 404

@app.route('/api/notifications/bulk-actions', methods=['POST'])
@jwt_required()
def bulk_notifications_action():
    user_id = get_jwt_identity()
    data = request.get_json()
    action = data.get('action')
    notif_ids = data.get('notif_ids', [])
    if not action or action not in ['mark_read', 'delete']:
        return jsonify(success=False, message=_("Invalid action.")), 400
    if not notif_ids:
        query = Notification.query.filter_by(user_id=user_id)
    else:
        query = Notification.query.filter(Notification.user_id == user_id, Notification.id.in_(notif_ids))
    items_to_process = query.all()
    if not items_to_process:
        return jsonify(success=True, message=_("No notifications to process."))
    if action == 'mark_read':
        for notif in items_to_process: notif.is_read = True
        message_verb = _('marked as read')
    elif action == 'delete':
        for notif in items_to_process: db.session.delete(notif)
        message_verb = _('deleted')
    db.session.commit()
    return jsonify(success=True, message=_("Notifications %(verb)s.", verb=message_verb))

@app.route('/api/locations')
def get_locations():
    if not Location.query.first():
        departments = ["Ngaoundéré", "Garoua", "Tignère", "Banyo", "Guider", "Meiganga", "Yokadouma", "Abong-Mbang", "Batouri", "Bertoua", "Mbouda", "Bafang", "Baham", "Bandjoun", "Dschang", "Bafoussam", "Bangangté", "Foumban", "Fundong", "Kumbo", "Nkambé", "Wum", "Bamenda", "Mbengwi", "Ndop", "Maroua", "Kousséri", "Yagoua", "Kaélé", "Mora", "Mokolo", "Limbé", "Bangem", "Menji", "Mamfé", "Kumba", "Mundemba", "Nanga-Eboko", "Monatélé", "Bafia", "Ntui", "Mfou", "Ngoumou", "Yaoundé", "Éséka", "Akonolinga", "Mbalmayo", "Poli", "Tcholliré", "Sangmélima", "Ebolowa", "Kribi", "Ambam", "Nkongsamba", "Yabassi", "Édéa", "Douala"]
        departments.sort()
        for dep_name in departments:
            if not Location.query.filter_by(name=dep_name).first():
                 db.session.add(Location(name=dep_name))
        db.session.commit()
    locations = Location.query.order_by(Location.name).all()
    return jsonify(success=True, locations=[loc.name for loc in locations])

@app.route('/api/user/default-location', methods=['GET'])
@jwt_required()
def get_user_default_location():
    user = db.session.get(User, int(get_jwt_identity()))
    if user and user.location:
        return jsonify(success=True, location=user.location)
    return jsonify(success=False, message=_("Default location not set.")), 404

@app.route('/api/translations')
def get_translations():
    lang = session.get('language', 'fr')
    translations = {}
    if lang == 'en':
        translations = { "Missing required fields": "Missing required fields", "Password does not meet security criteria.": "Password does not meet security criteria." }
    return jsonify(translations)

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    data = request.get_json()
    new_username = data.get('username')
    new_email = data.get('email')
    if new_username != user.username and User.query.filter_by(username=new_username).first():
        return jsonify(success=False, message=_("This username is already taken.")), 409
    if new_email != user.email and User.query.filter_by(email=new_email).first():
        return jsonify(success=False, message=_("This email address is already in use.")), 409
    user.username = new_username
    user.email = new_email
    db.session.commit()
    return jsonify(success=True, message=_("Profile updated successfully!"))

@app.route('/api/user/change_password', methods=['POST'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    data = request.get_json()
    current_password, new_password = data.get('current_password'), data.get('new_password')
    if not user.check_password(current_password):
        return jsonify(success=False, message=_("The current password is incorrect.")), 403
    if not is_password_strong(new_password):
         return jsonify(success=False, message=_("The new password does not meet security criteria.")), 400
    user.set_password(new_password)
    db.session.commit()
    return jsonify(success=True, message=_("Password changed successfully!"))

@app.route('/api/user/delete', methods=['DELETE'])
@jwt_required()
def delete_account():
    user_id_str = get_jwt_identity()
    user = db.session.get(User, int(user_id_str))
    password = request.get_json().get('password')
    if not user.check_password(password):
        return jsonify(success=False, message=_("The password is incorrect.")), 403
    try:
        Rating.query.filter((Rating.rater_id == user.id) | (Rating.rated_user_id == user.id)).delete(synchronize_session=False)
        Notification.query.filter((Notification.user_id == user.id) | (Notification.actor_id == user.id)).delete(synchronize_session=False)
        for chatroom in user.chatrooms: chatroom.participants.remove(user)
        PushSubscription.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting account for user {user.id}: {e}")
        return jsonify(success=False, message=_("An error occurred during account deletion.")), 500
    response = jsonify(success=True, message=_("Account deleted successfully."))
    unset_jwt_cookies(response)
    return response

@app.route('/api/posts/bulk-delete', methods=['POST'])
@jwt_required()
def bulk_delete_posts():
    user_id = get_jwt_identity()
    post_ids = request.get_json().get('post_ids', [])
    if not post_ids: return jsonify(success=False, message=_("No ad selected.")), 400
    posts_to_delete = Post.query.filter(Post.id.in_(post_ids), Post.user_id == user_id).all()
    for post in posts_to_delete: db.session.delete(post)
    db.session.commit()
    return jsonify(success=True, message=_("%(count)s ad(s) deleted.", count=len(posts_to_delete)))

@app.route('/api/posts/bulk-visibility', methods=['POST'])
@jwt_required()
def bulk_toggle_visibility():
    user_id = get_jwt_identity()
    data = request.get_json()
    post_ids, action = data.get('post_ids', []), data.get('action')
    if not post_ids or action not in ['hide', 'show']:
        return jsonify(success=False, message=_("Invalid action or selection.")), 400
    new_visibility = True if action == 'show' else False
    posts_to_update = Post.query.filter(Post.id.in_(post_ids), Post.user_id == user_id).update({'is_visible': new_visibility})
    db.session.commit()
    return jsonify(success=True, message=_("Visibility of %(count)s ad(s) updated.", count=posts_to_update))

@app.route('/api/save-subscription', methods=['POST'])
@jwt_required()
def save_subscription():
    user_id = get_jwt_identity()
    data = request.get_json()
    subscription = PushSubscription.query.filter_by(user_id=user_id).first()
    if subscription:
        subscription.subscription_info = json.dumps(data)
    else:
        subscription = PushSubscription(user_id=user_id, subscription_info=json.dumps(data))
        db.session.add(subscription)
    db.session.commit()
    return jsonify(success=True, message=_("Subscription saved."))

@app.route('/api/user/change_language', methods=['POST'])
@jwt_required()
def change_language():
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    lang = request.get_json().get('language')
    if lang and lang in app.config['LANGUAGES']:
        user.preferred_language = lang
        session['language'] = lang
        db.session.commit()
        return jsonify(success=True, message=_("Language updated successfully!"))
    return jsonify(success=False, message=_("Invalid language selected.")), 400
    
@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user:
        return jsonify(success=True, user=user.to_dict())
    return jsonify(success=False, message=_("User not found")), 401

# --- Événements SocketIO ---
def get_user_from_jwt_in_socket():
    cookie = request.cookies.get('access_token_cookie'); 
    if not cookie: return None
    try:
        from flask_jwt_extended import decode_token
        return db.session.get(User, int(decode_token(cookie)['sub']))
    except Exception: return None

@socketio.on('connect')
def on_connect():
    user = get_user_from_jwt_in_socket()
    if not user: return False
    join_room(str(user.id))
    logging.info(f"Client connecté: {request.sid}, User ID: {user.id}")

@socketio.on('disconnect')
def on_disconnect():
    user = get_user_from_jwt_in_socket()
    if user:
        leave_room(str(user.id))
    logging.info(f"Client déconnecté: {request.sid}")


@socketio.on('user_typing_status')
def on_user_typing_status(data):
    user = get_user_from_jwt_in_socket()
    if not user or not data.get('chatroom_id'): return
    chatroom_id = int(data['chatroom_id'])
    emit('typing_status_update', {'username': user.username, 'is_typing': data.get('is_typing', False)}, to=str(chatroom_id), skip_sid=request.sid)

@socketio.on('user_recording_status')
def on_user_recording_status(data):
    user = get_user_from_jwt_in_socket()
    if not user or not data.get('chatroom_id'): return
    chatroom_id = int(data['chatroom_id'])
    emit('recording_status_update', {'username': user.username, 'is_recording': data.get('is_recording', False)}, to=str(chatroom_id), skip_sid=request.sid)
# --- ÉVÉNEMENT À REMPLACER DANS app.py ---
@socketio.on('join')
def on_join(data):
    user = get_user_from_jwt_in_socket()
    if not user: return
    
    try: chatroom_id = int(data.get('chatroom_id'))
    except (ValueError, TypeError): return

    # Quitter les autres "rooms" de chat pour éviter les notifications croisées
    for room in rooms(request.sid):
        if str(room).isdigit() and str(room) != str(chatroom_id):
            leave_room(room)

    chatroom = db.session.get(Chatroom, chatroom_id)
    if not (chatroom and user in chatroom.participants): return

    join_room(str(chatroom_id))
    
    # Marquer les messages comme lus
    messages_to_update_status = MessageStatus.query.join(Message).filter(
        Message.chatroom_id == chatroom_id,
        MessageStatus.user_id == user.id,
        MessageStatus.is_read == False
    ).all()
    
    if messages_to_update_status:
        other_participant = next((p for p in chatroom.participants if p.id != user.id), None)
        
        # On ne met à 'read' que les messages envoyés par l'autre participant
        read_message_ids = [
            status.message_id for status in messages_to_update_status 
            if status.message.sender_id != user.id
        ]

        if read_message_ids:
            Message.query.filter(Message.id.in_(read_message_ids)).update(
                {'status': 'read'}, synchronize_session=False
            )
            # >>> LA CORRECTION CLÉ EST ICI <<<
            # On notifie l'expéditeur (l'autre participant) que ses messages ont été lus
            if other_participant:
                emit('bulk_status_update', {'message_ids': read_message_ids, 'status': 'read'}, to=str(other_participant.id))

        # On met à jour les statuts de lecture pour l'utilisateur actuel
        for status in messages_to_update_status:
            status.is_read = True
        
        db.session.commit()
        
    clear_entry = UserChatroomClear.query.filter_by(user_id=user.id, chatroom_id=chatroom.id).first()
    cleared_ts = clear_entry.cleared_at if clear_entry else None

    # On construit la requête pour l'historique
    messages_query = chatroom.messages.order_by(Message.timestamp.asc())
    if cleared_ts:
        # On ne récupère que les messages APRES la date d'effacement
        messages_query = messages_query.filter(Message.timestamp > cleared_ts)
    
    messages = messages_query.all()
    # --- FIN DE LA MODIFICATION ---
    
    emit('message_history', {'messages': [msg.to_dict() for msg in messages]}, to=request.sid)

@socketio.on('new_message')
def on_new_message(data):
    user = get_user_from_jwt_in_socket()
    if not user: return {'success': False, 'message': _('User not authenticated')}

    try: chatroom_id = int(data.get('chatroom_id'))
    except (ValueError, TypeError): return {'success': False, 'message': _('Invalid chatroom ID')}

    chatroom = db.session.get(Chatroom, chatroom_id)
    if not (chatroom and user in chatroom.participants):
        return {'success': False, 'message': _('Chatroom not found or user not a participant')}

    content = data.get('content', '').strip()
    file_path = data.get('file_path')
    file_type = data.get('file_type')
    replied_to_id = data.get('replied_to_id')

    if not content and not file_path: return {'success': False, 'message': _('Empty message')}

    new_message = Message(
        chatroom_id=chatroom.id, sender_id=user.id, content=content,
        file_path=file_path, file_type=file_type, replied_to_id=replied_to_id,
        status='sent' 
    )
    db.session.add(new_message)
    db.session.commit() # Commit pour avoir l'ID

    # --- DÉBUT DE LA CORRECTION ---
    # On n'émet plus à `to=str(chatroom.id)`.
    # On émet à la room personnelle de CHAQUE participant (y compris l'expéditeur).

    for p in chatroom.participants:
        # Envoie le message à la room personnelle de chaque participant (ex: '123' et '456')
        # L'expéditeur le reçoit (pour l'affichage) et le destinataire le reçoit (pour la mise à jour de la liste).
        emit('new_message', new_message.to_dict(), to=str(p.id))
        
        # Logique pour le destinataire
        if p.id != user.id:
            # Créer le statut "non lu"
            unread_status = MessageStatus(message_id=new_message.id, user_id=p.id, is_read=False)
            db.session.add(unread_status)
            
            # Envoyer la notification push (cette partie est inchangée)
            notification_text = f"{user.username}: {new_message.content[:50]}" if new_message.content else _("%(username)s sent you a file", username=user.username)
            link = url_for('messages_page', chatroom_id=chatroom.id, _external=True)
            send_notification(p.id, 'new_message', notification_text, link, actor_id=user.id, save_to_db=False)
            
    db.session.commit()
    # --- FIN DE LA CORRECTION ---
    
    # On renvoie l'URL finale du fichier si c'en est un, pour mise à jour côté client
    file_url = url_for('uploaded_file', filename=new_message.file_path, _external=True) if new_message.file_path else None
    
    return {'success': True, 'message_id': new_message.id, 'timestamp': new_message.timestamp.isoformat(), 'status': 'sent', 'file_url': file_url}

@socketio.on('message_delivered')
def on_message_delivered(data):
    user = get_user_from_jwt_in_socket() # L'utilisateur qui a reçu le message
    if not user or not data.get('message_id'): return

    try: message_id = int(data['message_id'])
    except (ValueError, TypeError): return

    message = db.session.get(Message, message_id)
    # On met à jour uniquement si le statut est 'sent' pour éviter des écritures inutiles
    if message and message.status == 'sent':
        message.status = 'delivered'
        db.session.commit()
        # On notifie l'expéditeur que le message a été distribué
        emit('message_status_updated', {'message_id': message.id, 'status': 'delivered'}, to=str(message.sender_id))

@socketio.on('mark_as_read')
def on_mark_as_read(data):
    user = get_user_from_jwt_in_socket()
    if not user or not data.get('message_id'): return

    message_id = data['message_id']
    message = db.session.get(Message, message_id)
    if not message: return
    
    # On met à jour le statut du message lui-même que s'il n'est pas déjà "read"
    if message.status != 'read':
        message.status = 'read'
        db.session.commit()
        # On notifie l'expéditeur du changement de statut
        emit('message_status_updated', {'message_id': message.id, 'status': 'read'}, to=str(message.sender_id))

    # On met à jour le MessageStatus pour l'utilisateur actuel
    status = MessageStatus.query.filter_by(message_id=message_id, user_id=user.id).first()
    if status and not status.is_read:
        status.is_read = True
        db.session.commit()
        
    # On met à jour le compteur de non-lus pour l'utilisateur actuel
    total_unread = MessageStatus.query.filter_by(user_id=user.id, is_read=False).count()
    emit('unread_count_update', {'total_unread': total_unread}, to=str(user.id))
    
@socketio.on('delete_message')
def on_delete_message(data):
    user = get_user_from_jwt_in_socket()
    if not user: return
    message_id = data.get('message_id')
    message = db.session.get(Message, message_id)
    if message and message.sender_id == user.id:
        chatroom_id = message.chatroom_id
        db.session.delete(message)
        db.session.commit()
        emit('message_deleted', {'message_id': message_id}, to=str(chatroom_id))

@socketio.on('delete_multiple_messages')
def on_delete_multiple_messages(data):
    user = get_user_from_jwt_in_socket()
    if not user: return
    
    message_ids = data.get('message_ids', [])
    if not message_ids: return

    messages_to_delete = Message.query.filter(Message.id.in_(message_ids), Message.sender_id == user.id).all()
    if not messages_to_delete: return
    
    chatroom_id = messages_to_delete[0].chatroom_id
    deleted_ids = [msg.id for msg in messages_to_delete]
    
    for msg in messages_to_delete:
        db.session.delete(msg)
    
    db.session.commit()
    emit('messages_deleted', {'message_ids': deleted_ids}, to=str(chatroom_id))

# --- Démarrage de l'application ---
if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

<< search_service.py >>:  
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import os
import pickle
import re

# (MODIFICATION) On passe à un modèle d'IA beaucoup plus puissant
MODEL_NAME = 'all-MiniLM-L6-v2'
INDEX_FILE = 'faiss_index.bin'
MAP_FILE = 'faiss_map.pkl'

# Seuil de similarité ajusté pour le nouveau modèle
SIMILARITY_THRESHOLD = 0.45

def _preprocess_text(text):
    text = text.lower()
    text = re.sub(r'[^\w\s]', ' ', text) # Remplace la ponctuation par des espaces
    text = re.sub(r'\s+', ' ', text).strip() # Supprime les espaces multiples
    return text

class SearchService:
    def __init__(self):
        print(f"Chargement du modèle de recherche sémantique: {MODEL_NAME}...")
        self.model = SentenceTransformer(MODEL_NAME)
        self.index = None
        self.id_map = []
        self.load_index()
        print("Modèle et index chargés.")

    def load_index(self):
        if os.path.exists(INDEX_FILE) and os.path.exists(MAP_FILE):
            print(f"Chargement de l'index depuis le fichier '{INDEX_FILE}'...")
            self.index = faiss.read_index(INDEX_FILE)
            with open(MAP_FILE, 'rb') as f:
                self.id_map = pickle.load(f)
        else:
            print("Aucun index trouvé. Il devra être créé.")

    def build_index(self, posts):
        print("Création de l'index sémantique à partir des annonces...")
        if not posts:
            print("Aucune annonce à indexer.")
            return

        texts = [_preprocess_text(f"{post.title}. {post.description}") for post in posts]
        
        embeddings = self.model.encode(texts, convert_to_tensor=True, show_progress_bar=True)
        embeddings_np = embeddings.cpu().numpy().astype('float32')
        faiss.normalize_L2(embeddings_np)
        
        embedding_dim = embeddings_np.shape[1]
        self.index = faiss.IndexIDMap(faiss.IndexFlatIP(embedding_dim))
        
        self.id_map = [post.id for post in posts]
        ids_array = np.array(self.id_map, dtype='int64')

        self.index.add_with_ids(embeddings_np, ids_array)
        
        faiss.write_index(self.index, INDEX_FILE)
        with open(MAP_FILE, 'wb') as f:
            pickle.dump(self.id_map, f)
        
        print(f"Index créé et sauvegardé avec {len(posts)} annonces.")

    def semantic_search(self, query, k=20):
        if self.index is None or self.index.ntotal == 0:
            return []

        processed_query = _preprocess_text(query)
        
        query_embedding = self.model.encode([processed_query], convert_to_tensor=True)
        query_embedding_np = query_embedding.cpu().numpy().astype('float32')
        faiss.normalize_L2(query_embedding_np)

        # On recherche un peu plus de résultats pour avoir de la marge avec le seuil
        search_k = min(k * 2, self.index.ntotal)
        distances, ids = self.index.search(query_embedding_np, k=search_k)

        relevant_ids = [int(id_) for id_, dist in zip(ids[0], distances[0]) if dist > SIMILARITY_THRESHOLD]
        
        # On ne retourne que les 'k' meilleurs résultats
        return relevant_ids[:k]

search_service = SearchService()


==================
JAVASCRIPT COMPLET
==================

<< auth_check.js >>:  
// static/js/auth_check.js (Version corrigée et nettoyée)

// --- Fonctions globales ---

window.getCsrfToken = function() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        let [name, value] = cookie.split('=').map(c => c.trim());
        if (name === 'csrf_access_token') return value;
    }
    return null;
};

window.logout = async function() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken()}
        });
        const data = await response.json();
        if (data.success) {
            localStorage.clear();
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Network error on logout:', error);
    }
};

window.displayMessage = function(message, type, containerId = 'message-container') {
    const container = document.getElementById(containerId);
    if (!container) return;
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    container.innerHTML = '';
    container.appendChild(messageDiv);
    setTimeout(() => {
        messageDiv.style.opacity = '0';
        setTimeout(() => messageDiv.remove(), 500);
    }, 5000);
};

function showToast(message, link = null) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('a');
    toast.className = 'toast';
    toast.textContent = message;

    if (link) {
        toast.href = link;
        toast.classList.add('clickable');
    }

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4500);
}

function updateUnreadCountBadge(total_unread) {
    console.log('Updating message badge with total:', total_unread);

    // Cible le lien texte "Messages" (desktop)
    const messagesLinkDesktop = document.querySelector('.center-desktop-nav a[href="/messages"]');
    if (messagesLinkDesktop) { // CORRECTION : On vérifie si l'élément existe
        messagesLinkDesktop.querySelector('.nav-notification-badge')?.remove();
        if (total_unread > 0) {
            const badge = document.createElement('span');
            badge.className = 'nav-notification-badge';
            badge.textContent = total_unread > 9 ? '9+' : total_unread;
            messagesLinkDesktop.style.position = 'relative';
            messagesLinkDesktop.appendChild(badge);
        }
    }

    // Cible l'icône messages mobile
    const mobileMessagesIcon = document.querySelector('.mobile-nav-item[href="/messages"]');
    if (mobileMessagesIcon) { // CORRECTION : On vérifie si l'élément existe
        mobileMessagesIcon.querySelector('.nav-notification-badge')?.remove();
        if (total_unread > 0) {
            const badge = document.createElement('span');
            badge.className = 'nav-notification-badge';
            badge.textContent = total_unread > 9 ? '9+' : total_unread;
            mobileMessagesIcon.appendChild(badge);
        }
    }
}

function updateNotificationBadge(unread) {
    const bell = document.querySelector('.notification-bell');
    // CORRECTION MAJEURE : Si la cloche de notification n'existe pas sur la page, on ne fait rien.
    if (!bell) {
        return;
    }
    bell.querySelector('.nav-notification-badge')?.remove();
    if (unread > 0) {
        const badge = document.createElement('span');
        badge.className = 'nav-notification-badge';
        badge.textContent = unread > 9 ? '9+' : unread;
        bell.appendChild(badge);
    }
}


function setupGlobalSocketListeners() {
    // NOTE : On s'assure de n'avoir qu'une seule connexion socket
    if (window.socket) return;
    
    window.socket = io();

    window.socket.on('connect', () => {
        console.log("Socket.IO global connected.");
    });

    window.socket.on('unread_count_update', (data) => {
        updateUnreadCountBadge(data.total_unread);
    });

    window.socket.on('new_notification', (data) => {
        if (data.link && data.link.startsWith('/messages') && window.location.pathname === '/messages') {
            return;
        }
        showToast(data.message, data.link);
    });

    window.socket.on('notification_count_update', (data) => {
        console.log("Notification badge update received:", data.unread_count);
        updateNotificationBadge(data.unread_count);
    });
}

function fetchInitialUnreadCounts() {
    // Récupère les messages non lus
    fetch('/api/chat/unread_info')
        .then(res => res.ok ? res.json() : Promise.reject('Failed to fetch unread messages'))
        .then(data => {
            if (data.success) {
                updateUnreadCountBadge(data.total_unread);
            }
        }).catch(e => console.error("Failed to fetch unread info:", e));

    // Récupère les notifications non lues
    fetch('/api/notifications/unread')
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                updateNotificationBadge(data.unread_count);
            }
        }).catch(e => console.error("Failed to fetch unread notifications:", e));
}

async function checkAuthState() {
    try {
        const response = await fetch('/api/auth_status');
        const data = await response.json();
        
        if (data.is_logged_in) {
            localStorage.setItem('user_id', data.user_id);
            // On lance les logiques "connectées" UNIQUEMENT si l'utilisateur est bien connecté
            setupGlobalSocketListeners();
            fetchInitialUnreadCounts();
        } else {
            localStorage.removeItem('user_id');
        }
    } catch (error) {
        localStorage.removeItem('user_id');
        console.error("Auth check failed:", error);
    }
}


// --- Logique principale au chargement de la page ---
document.addEventListener('DOMContentLoaded', () => {
    // Bouton de déconnexion
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', (event) => {
            event.preventDefault();
            window.logout();
        });
    }

    // Clic sur la cloche de notification
    const notificationBell = document.querySelector('.notification-bell');
    if (notificationBell) {
        notificationBell.addEventListener('click', () => {
            const badge = notificationBell.querySelector('.nav-notification-badge');
            if (badge) {
                badge.style.display = 'none';
            }
        });
    }

    // On vérifie le statut de l'authentification UNE SEULE FOIS, proprement.
    checkAuthState();
});

<< create_post.js >>:  
document.addEventListener('DOMContentLoaded', () => {
    const createPostForm = document.getElementById('createPostForm');
    const fileInput = document.getElementById('file');
    const previewContainer = document.getElementById('image-preview-container');
    const pillButtons = document.querySelectorAll('.pill-btn');

    let selectedCategory = null;
    let selectedType = null;
    let selectedFiles = [];
    let locationChoicesInstance = null;

    // --- INITIALISATION DU SÉLECTEUR DE LOCALISATION ---
    window.initAdvancedLocationSelector('location-selector', true).then(instance => {
        locationChoicesInstance = instance;
        if (locationChoicesInstance) {
            // Pré-remplir avec la localisation par défaut
            fetch('/api/user/default-location')
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.location) {
                        locationChoicesInstance.setValue([data.location]);
                    }
                }).catch(err => console.warn('Failed to load default location:', err));
        }
    }).catch(err => console.error('Failed to init location selector:', err));

    // --- GESTION DES BOUTONS "PILLULES" (Catégorie & Type) ---
    pillButtons.forEach(button => {
        button.addEventListener('click', () => {
            const group = button.parentElement;
            group.querySelectorAll('.pill-btn').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            if (button.dataset.category) {
                selectedCategory = button.dataset.category;
            }
            if (button.dataset.type) {
                selectedType = button.dataset.type;
            }
        });
    });

    // --- LOGIQUE DE PRÉVISUALISATION DES IMAGES ---
    fileInput.addEventListener('change', () => {
        handleFiles(fileInput.files);
    });
    
    function handleFiles(files) {
        for (const file of files) {
            if (selectedFiles.length < 5) { // Limite de 5 images
                selectedFiles.push(file);
            }
        }
        renderPreviews();
        updateFileInput();
    }

    function renderPreviews() {
        previewContainer.innerHTML = '';
        selectedFiles.forEach((file, index) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const previewWrapper = document.createElement('div');
                previewWrapper.className = 'image-preview';
                previewWrapper.innerHTML = `
                    <img src="${e.target.result}" alt="${file.name}">
                    <button type="button" class="remove-image-btn" data-index="${index}">&times;</button>
                    ${index === 0 ? `<span class="cover-badge">${_('Cover')}</span>` : ''}
                `;
                previewContainer.appendChild(previewWrapper);
            };
            reader.readAsDataURL(file);
        });
    }

    previewContainer.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-image-btn')) {
            const indexToRemove = parseInt(e.target.dataset.index, 10);
            selectedFiles.splice(indexToRemove, 1);
            renderPreviews();
            updateFileInput();
        }
    });

    function updateFileInput() {
        const dataTransfer = new DataTransfer();
        selectedFiles.forEach(file => dataTransfer.items.add(file));
        fileInput.files = dataTransfer.files;
    }


    // --- LOGIQUE DE SOUMISSION DU FORMULAIRE ---
    if (createPostForm) {
        createPostForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            // Validation
            if (!selectedCategory || !selectedType) {
                displayMessage(_('Please select a category and a type for the ad.'), 'error');
                return;
            }

            const submitButton = createPostForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.innerHTML = `<div class="spinner-small"></div> ${'Publishing...'}`;
            
            const image_paths = [];

            for (const file of selectedFiles) {
                const formData = new FormData();
                formData.append('file', file);
                try {
                    const uploadResponse = await fetch('/api/chat/upload', {
                        method: 'POST',
                        headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                        body: formData
                    });
                    const uploadData = await uploadResponse.json();
                    if (!uploadData.success) throw new Error(uploadData.message);
                    image_paths.push(uploadData.file_path);
                } catch (error) {
                    displayMessage(error.message, 'error');
                    submitButton.disabled = false;
                    submitButton.innerHTML = `${_('Publish my Ad')} <i class="fa-solid fa-rocket"></i>`;
                    return;
                }
            }
            
            const locationsValue = locationChoicesInstance ? locationChoicesInstance.getValue(true) : [];
            
            const postData = {
                title: createPostForm.title.value,
                description: createPostForm.description.value,
                type: selectedType,
                category: selectedCategory,
                locations: locationsValue,
                image_paths: image_paths
            };

            try {
                const response = await fetch('/api/posts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify(postData)
                });
                const data = await response.json();
                if (data.success) {
                    window.location.href = `/posts/${data.post.id}`;
                } else {
                    throw new Error(data.message);
                }
            } catch (error) {
                displayMessage(error.message || _("Error creating ad."), 'error');
                submitButton.disabled = false;
                submitButton.innerHTML = `${_('Publish my Ad')} <i class="fa-solid fa-rocket"></i>`;
            }
        });
    }
});

<< dark_mode.js >>:  
// dans static/js/dark_mode.js

document.addEventListener('DOMContentLoaded', () => {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const currentTheme = localStorage.getItem('theme');

    // Appliquer le thème sauvegardé au chargement de la page
    if (currentTheme === 'dark') {
        document.body.classList.add('dark-mode');
        if (darkModeToggle) {
            darkModeToggle.checked = true;
        }
    }

    // Gérer le clic sur l'interrupteur
    if (darkModeToggle) {
        darkModeToggle.addEventListener('change', () => {
            if (darkModeToggle.checked) {
                document.body.classList.add('dark-mode');
                localStorage.setItem('theme', 'dark');
            } else {
                document.body.classList.remove('dark-mode');
                localStorage.setItem('theme', 'light');
            }
        });
    }
});

<< edit_post.js >>:  
// DANS static/js/edit_post.js
// REMPLACEZ TOUT LE CONTENU DU FICHIER PAR CE CODE :

document.addEventListener('DOMContentLoaded', async () => {
    const editPostForm = document.getElementById('editPostForm');
    const postId = document.getElementById('postId').value;
    const imagePreviewContainer = document.getElementById('image-preview-container');
    const fileInput = document.getElementById('file');
    
    let existingImagePaths = [];
    // On initialise le sélecteur de localisation en mode multiple
    const locationChoicesInstance = await initAdvancedLocationSelector('location-selector', true);

    // --- Fonctions ---

    function renderImagePreviews() {
        imagePreviewContainer.innerHTML = '';
        existingImagePaths.forEach((path, index) => {
            if (!path) return;
            const preview = document.createElement('div');
            preview.className = 'image-preview';
            preview.innerHTML = `
                <img src="/uploads/${path}" alt="Existing image">
                <button type="button" class="remove-image-btn" data-index="${index}" title="Delete image">&times;</button>
            `;
            imagePreviewContainer.appendChild(preview);
        });
        document.querySelectorAll('.remove-image-btn').forEach(button => {
            button.addEventListener('click', (event) => {
                const indexToRemove = parseInt(event.target.dataset.index, 10);
                existingImagePaths.splice(indexToRemove, 1);
                renderImagePreviews();
            });
        });
    }

    async function loadPostData() {
        try {
            const response = await fetch(`/api/posts/${postId}`);
            const data = await response.json();
            if (data.success) {
                const post = data.post;
                editPostForm.title.value = post.title;
                editPostForm.description.value = post.description;
                editPostForm.type.value = post.type;
                editPostForm.category.value = post.category;
                
                // On pré-remplit le sélecteur de localisation avec les valeurs de l'annonce
                if (locationChoicesInstance && post.locations) {
                    locationChoicesInstance.setValue(post.locations);
                }

                existingImagePaths = post.image_urls.map(url => url.split('/').pop());
                renderImagePreviews();
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            displayMessage(error.message || _("Unable to load post data."), 'error');
        }
    }

    // --- Logique principale ---

    editPostForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const submitButton = editPostForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.textContent = _('Uploading...');

        const newImagePaths = [];

        if (fileInput.files.length > 0) {
            for (const file of fileInput.files) {
                const formData = new FormData();
                formData.append('file', file);
                try {
                    const uploadResponse = await fetch('/api/upload', {
                        method: 'POST',
                        headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                        body: formData
                    });
                    const uploadData = await uploadResponse.json();
                    if (uploadData.success) {
                        newImagePaths.push(uploadData.file_path);
                    } else { throw new Error(uploadData.message); }
                } catch (error) {
                    displayMessage(error.message || `Upload error for ${file.name}.`, 'error');
                    submitButton.disabled = false;
                    submitButton.textContent = _("Update the ad");
                    return;
                }
            }
        }

        submitButton.textContent = _('Updating...');
        
        // On récupère le tableau des localisations mises à jour
        const locationsValue = locationChoicesInstance ? locationChoicesInstance.getValue(true) : [];

        const updatedData = {
            title: editPostForm.title.value,
            description: editPostForm.description.value,
            type: editPostForm.type.value,
            category: editPostForm.category.value,
            locations: locationsValue, // On envoie le nouveau tableau de localisations
            image_paths: [...existingImagePaths, ...newImagePaths]
        };

        try {
            const response = await fetch(`/api/posts/${postId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify(updatedData)
            });
            const result = await response.json();
            if (result.success) {
                displayMessage(_('Ad updated successfully!'), 'success');
                setTimeout(() => { window.location.href = '/my_posts'; }, 1500);
            } else {
                throw new Error(result.message);
            }
        } catch (error) {
            displayMessage(error.message || _('Error updating.'), 'error');
            submitButton.disabled = false;
            submitButton.textContent = _("Update the ad");
        }
    });

    loadPostData();
});

<< favorites.js >>:  
// static/js/favorites.js (Version avec menu d'actions)

document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('favorites-list-container');
    const actionsMenu = document.querySelector('.actions-menu');
    const actionsButton = document.querySelector('.actions-button');
    const actionsDropdown = document.querySelector('.actions-dropdown');
    const clearFavoritesButton = document.getElementById('clear-favorites-button');
    let page = 1;
    let hasMore = true;
    let isLoading = false;

    async function toggleFavorite(postId, buttonElement) {
        const csrfToken = window.getCsrfToken();
        if (!csrfToken) {
            window.location.href = '/login';
            return;
        }
        try {
            const response = await fetch(`/api/posts/${postId}/favorite`, {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': csrfToken }
            });
            const data = await response.json();
            if (data.success && data.status === 'removed') {
                buttonElement.closest('.post-card').remove();
                if (container.children.length === 0) {
                    container.innerHTML = "<p>" + _("You have no ad in your favorites.") + "</p>";
                }
            }
        } catch (error) {
            console.error(_("Error removing favorite:"), error);
        }
    }
    
    container.addEventListener('click', async (event) => {
        const favoriteBtn = event.target.closest('.favorite-btn');
        if (favoriteBtn) {
            event.preventDefault(); 
            const postId = favoriteBtn.dataset.postId;
            toggleFavorite(postId, favoriteBtn);
        }
    });

    async function fetchFavorites() {
        if (!hasMore || isLoading) return;
        isLoading = true;
        if (page === 1) displayMessage(_('Loading...'), 'info');

        const url = new URL('/api/favorites', window.location.origin);
        url.searchParams.append('page', page);

        try {
            const response = await fetch(url, { headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } });
            if (response.status === 401) { window.location.href = '/login'; return; }
            const data = await response.json();
            
            if (page === 1) document.getElementById('message-container').innerHTML = '';

            if (data.success) {
                renderPosts(data.posts);
                hasMore = data.has_next;
                page++;
                if (!hasMore && container.children.length === 0) {
                     container.innerHTML = "<p>" + _("You have no ad in your favorites.") + "</p>";
                }
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(_('Network error.'), 'error');
        } finally {
            isLoading = false;
        }
    }

    // REMPLACEZ la fonction renderPosts dans posts.js, home.js, et favorites.js

// REMPLACEZ la fonction renderPosts dans vos 3 fichiers JS par celle-ci

// REMPLACEZ la fonction renderPosts dans vos 3 fichiers JS (home.js, posts.js, favorites.js) par celle-ci

function renderPosts(posts) {
    // Si la page est la première et qu'il n'y a aucun post, on affiche un message.
    if (posts.length === 0 && page === 1) { // 'page' doit être défini dans le scope de chaque fichier
        const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
        if(container) container.innerHTML = '<p>' + _("No ad found.") + '</p>';
        return;
    }

    posts.forEach(post => {
        const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
        if (!container) return;
        
        const favoritedClass = post.is_favorited ? 'favorited' : '';
        let authorAvatarHTML = post.author_photo_url ?
            `<a href="#" class="author-avatar-link" data-img-url="${post.author_photo_url}" title="${_('View photo')}"><img src="${post.author_photo_url}" class="author-photo-small"></a>` :
            `<div class="author-initial-small">${post.author_username.charAt(0).toUpperCase()}</div>`;

        // *** LA MODIFICATION EST ICI ***
        // On ajoute le paramètre ?from_post=${post.id} au lien du profil
        const profileLink = `/profile/${post.author_username}?from_post=${post.id}`;
        const locationsHTML = post.locations && post.locations.length > 0 ? `
            <div class="post-card-location">
                <i class="fa-solid fa-map-marker-alt"></i>
                <span>${post.locations.join(', ')}</span>
            </div>
        ` : '';

        const postCardHTML = `
            <div class="post-card">
                <button class="favorite-btn ${favoritedClass}" data-post-id="${post.id}" title="${_('Save')}">
                    <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
                </button>
                <a href="/posts/${post.id}" class="post-card-link">
                    ${post.cover_image_url ? `<div class="post-card-image" style="background-image: url('${post.cover_image_url}');"></div>` : ''}
                    <div class="post-card-content">
                        <span class="post-card-category category-${post.category.toLowerCase()}">${post.category}</span>
                        <h3>${post.title}</h3>
                        ${locationsHTML} 
                    </div>
                </a>
                <div class="post-card-footer-new">
                    <div class="footer-left">
                        ${authorAvatarHTML}
                        <a href="${profileLink}" title="${_('View profile')}">${post.author_username}</a>
                    </div>
                    <div class="footer-center interactive-footer-item" 
     data-message="${_('%(count)s people interact with this ad.', {count: post.interest_count})}" 
     data-author-id="${post.user_id}" 
     data-post-id="${post.id}" 
     title="${_('View interactions')}">
                        <i class="fa-solid fa-comments"></i>
                        <span>${post.interest_count}</span>
                    </div>
                    <div class="footer-right interactive-footer-item" data-message="${_('This ad has been viewed %(count)s times.', {count: post.view_count})}" title="${_('View views')}">
                        <i class="fa-solid fa-eye"></i>
                        <span>${post.view_count}</span>
                    </div>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', postCardHTML);
    });
}

    window.addEventListener('scroll', () => {
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 200) {
            fetchFavorites();
        }
    });

    // --- GESTION DU MENU D'ACTIONS ---
    actionsButton.addEventListener('click', (event) => {
        event.stopPropagation();
        actionsDropdown.classList.toggle('show');
    });

    clearFavoritesButton.addEventListener('click', async () => {
        if (confirm(_('Are you sure you want to clear your favorites list? This action is irreversible.'))) {
            try {
                const response = await fetch('/api/favorites/clear', {
                    method: 'POST',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() }
                });
                const data = await response.json();
                if (data.success) {
                    container.innerHTML = "<p>" + _("Your favorites list has been cleared.") + "</p>";
                } else {
                    displayMessage(data.message, 'error');
                }
            } catch (error) {
                displayMessage(_('Network error during deletion.'), 'error');
            } finally {
                actionsDropdown.classList.remove('show');
            }
        }
    });

    document.addEventListener('click', () => {
        if (actionsDropdown.classList.contains('show')) {
            actionsDropdown.classList.remove('show');
        }
    });

    fetchFavorites();
});

<< forgot_password.js >>:  
// static/js/forgot_password.js

document.addEventListener('DOMContentLoaded', () => {
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');

    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const email = forgotPasswordForm.email.value;
            const submitButton = forgotPasswordForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.textContent = _('Sending...');

            try {
                const response = await fetch('/api/request_password_reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email })
                });

                const data = await response.json();
                
                // --- MODIFIÉ ---
                // On affiche un message plus patient et informatif
                if (data.success) {
                    displayMessage(_("Si un compte existe, un email a été envoyé. Cela peut prendre 1 à 2 minutes."), 'success');
                } else {
                    displayMessage(data.message, 'error');
                }

            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error');
            } finally {
                // On ne réactive pas le bouton immédiatement pour éviter le spam
                setTimeout(() => {
                    submitButton.disabled = false;
                    submitButton.textContent = _('Send the reset link');
                }, 30000); // 30 secondes d'attente
            }
        });
    }
});

<< geolocation.js >>:  
// static/js/geolocation.js (Version AVANCÉE & AUTOMATIQUE - Scoped avec Exposition Fiable)

(function() {
    // Mapping statique : Département (ex. "Mifi") ? Chef-lieu (ex. "Bafoussam")
    const departmentToCapitalMap = {
        "Bamboutos": "Mbouda",
        "Bénoué": "Garoua",
        "Boumba-et-Ngoko": "Yokadouma",
        "Boyo": "Fundong",
        "Bui": "Kumbo",
        "Diamaré": "Maroua",
        "Dja-et-Lobo": "Sangmelima",
        "Djerem": "Tibati",
        "Donga-Mantung": "Nkambé",
        "Fako": "Limbe",
        "Faro": "Poli",
        "Faro-et-Déo": "Tignere",
        "Haute-Sanaga": "Nanga-Eboko",
        "Haut-Nkam": "Bafang",
        "Haut-Nyong": "Abong-Mbang",
        "Hauts-Plateaux": "Baham",
        "Kadey": "Batouri",
        "Koung-Khi": "Badjoun",
        "Koupé-Manengouba": "Bangem",
        "Lebialem": "Menji",
        "Lekié": "Monatele",
        "Logone-et-Chari": "Kousseri",
        "Lom-et-Djerem": "Bertoua",
        "Manyu": "Mamfe",
        "Mayo-Banyo": "Banyo",
        "Mayo-Danay": "Yagoua",
        "Mayo-Kani": "Kaele",
        "Mayo-Louti": "Guider",
        "Mayo-Rey": "Tcholliré",
        "Mayo-Sava": "Mora",
        "Mayo-Tsanaga": "Mokolo",
        "Mbam-et-Inoubou": "Bafia",
        "Mbam-et-Kim": "Ntui",
        "Mbéré": "Meinganga",
        "Mefou-et-Afamba": "Mfou",
        "Mefou-et-Akono": "Ngoumou",
        "Meme": "Kumba",
        "Menchum": "Wum",
        "Menoua": "Dschang",
        "Mezam": "Bamenda",
        "Mfoundi": "Yaoundé",
        "Mifi": "Bafoussam",
        "Momo": "Mbengwi",
        "Moungo": "Nkongsamba",
        "Mvila": "Ebolowa",
        "Ndian": "Mundemba",
        "Ndé": "Bangangte",
        "Ngo-Ketunjia": "Ndop",
        "Nkam": "Yabassi",
        "Noun": "Foumban",
        "Nyong-et-Kéllé": "Eseka",
        "Nyong-et-Mfoumou": "Akonolinga",
        "Nyong-et-So'o": "Mbalmayo",
        "Océan": "Kribi",
        "Sanaga-Maritime": "Edéa",
        "Vallée-du-Ntem": "Ambam",
        "Vina": "Ngaoundéré",
        "Wouri": "Douala"
    };

    async function initAdvancedLocationSelector(selectorId, multiple = false) {
        const selectElement = document.getElementById(selectorId);
        if (!selectElement) {
            console.warn('Select element not found:', selectorId);
            return null;
        }

        // Garde contre réinitialisation multiple
        if (selectElement.hasAttribute('data-choices-initialized')) {
            console.warn('Location selector already initialized');
            return selectElement._choicesInstance || null;
        }
        selectElement.setAttribute('data-choices-initialized', 'true');

        console.log('Initializing location selector... (multiple:', multiple, ')');

        // Config Choices adaptée pour multiple/single
        const choicesConfig = {
            searchEnabled: true,
            itemSelectText: _('Press to select'),
            placeholder: true,
            placeholderValue: _('Detecting location...'),
            shouldSort: false,
            removeItemButton: multiple,  // Bouton X pour multiple
            maxItemCount: multiple ? -1 : 1,  // Illimité pour multiple, 1 pour single
            noChoicesText: _('No locations available'),
            noResultsText: _('No results found')
        };

        const choices = new Choices(selectElement, choicesConfig);
        if (choices && typeof choices.disable === 'function') {
            choices.disable();
        }

        // Stocke l'instance sur l'élément pour récupération future
        selectElement._choicesInstance = choices;

        try {
            // 1. Récupérer la liste complète des départements depuis notre API
            console.log('Fetching locations from API...');
            const response = await fetch('/api/locations', { credentials: 'include' });
            if (!response.ok) {
                throw new Error(`API error: ${response.status} ${response.statusText}`);
            }
            const departmentsData = await response.json();
            if (!departmentsData.success) {
                throw new Error("Could not fetch departments.");
            }

            const allDepartments = departmentsData.locations;
            if (!Array.isArray(allDepartments) || allDepartments.length === 0) {
                throw new Error("No departments data received from API.");
            }
            console.log('API locations loaded:', allDepartments.length, 'departments');

            let finalChoices = allDepartments.map(dep => ({ value: dep, label: dep }));

            // 2. Tenter d'obtenir la position de l'utilisateur (avec checks avancés)
            if ('geolocation' in navigator) {
                console.log('Geolocation API supported');
                
                // Vérifier l'état des permissions avant de lancer
                try {
                    const permissionStatus = await navigator.permissions.query({ name: 'geolocation' });
                    console.log('Geolocation permission state:', permissionStatus.state);
                    
                    if (permissionStatus.state === 'denied') {
                        console.warn('Geolocation denied - skipping detection');
                        handleFallback(choices, finalChoices, _('Select your department... (Geolocation blocked)'));
                        return choices;
                    } else if (permissionStatus.state === 'granted') {
                        console.log('Geolocation already granted - proceeding');
                    }
                    // 'prompt' : On lance getCurrentPosition, qui déclenchera le prompt
                } catch (permError) {
                    console.warn('Permissions API not supported:', permError);
                    // Fallback : Lancer quand même getCurrentPosition
                }

                // Wrapper async pour getCurrentPosition (pour await)
                const getPositionAsync = () => new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject, {
                        enableHighAccuracy: true,
                        timeout: 10000,
                        maximumAge: 60000
                    });
                });

                try {
                    console.log('Requesting current position...');
                    const position = await getPositionAsync();
                    console.log('Position obtained:', position.coords.latitude, position.coords.longitude);
                    
                    const { latitude, longitude } = position.coords;
                    
                    // 3. Traduire les coordonnées en nom de département via OpenStreetMap
                    console.log('Geocoding position...');
                    const geoResponse = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&accept-language=fr`);
                    if (!geoResponse.ok) {
                        console.warn('Geocoding failed:', geoResponse.status);
                        handleFallback(choices, finalChoices, _('Select your department...'));
                        return choices;
                    }
                    const geoData = await geoResponse.json();
                    console.log('Geocoding result:', geoData);
                    
                    if (geoData && geoData.address && geoData.address.county) {
                        let userLocation = geoData.address.county;
                        console.log('Detected department:', userLocation);

                        // Mapping vers chef-lieu si c'est un département
                        let finalUserLocation = userLocation;
                        if (departmentToCapitalMap[userLocation]) {
                            finalUserLocation = departmentToCapitalMap[userLocation];
                            console.log('Mapped department to capital:', userLocation, '?', finalUserLocation);
                        }

                        if (allDepartments.includes(finalUserLocation)) {
                            // Pré-sélection automatique (selected: true pour single, push pour multiple)
                            const autoSelected = { value: finalUserLocation, label: `${finalUserLocation} (${_('Current position')})` };
                            if (!multiple) {
                                autoSelected.selected = true;
                                finalChoices = [autoSelected, ...allDepartments.filter(d => d !== finalUserLocation).map(dep => ({ value: dep, label: dep }))];
                            } else {
                                finalChoices.unshift(autoSelected);  // Ajoute en premier pour multiple
                            }
                            console.log('Auto-selected:', finalUserLocation);
                        } else {
                            console.warn('Mapped location not in list:', finalUserLocation);
                        }
                    } else {
                        console.warn('No county in geocoding response');
                    }
                    
                    updateChoices(choices, finalChoices, _('Select your department...'));
                    return choices;
                    
                } catch (geoError) {
                    console.error('Geolocation error details:', geoError);
                    if (geoError.code === 1) { // PERMISSION_DENIED
                        console.warn('Permission denied - user must allow in browser settings');
                        handleFallback(choices, finalChoices, _('Select your department... (Allow location access?)'));
                    } else {
                        console.warn(`Geolocation error: ${geoError.message}`);
                        handleFallback(choices, finalChoices, _('Select your department...'));
                    }
                    return choices;
                }
            } else {
                console.warn('Geolocation not supported in this browser');
                handleFallback(choices, finalChoices, _('Select your department... (Not supported)'));
                return choices;
            }

        } catch (error) {
            console.error("Failed to initialize location selector:", error);
            if (choices && typeof choices.enable === 'function') {
                choices.enable();
            }
            updateChoices(choices, [], _('Error loading locations'));
            return choices;
        }
    }

    // Fonction helper pour fallback sans geolocation
    function handleFallback(choices, finalChoices, placeholderText) {
        console.log('Using fallback - no geolocation');
        updateChoices(choices, finalChoices, placeholderText);
    }

    // Fonction helper pour mettre à jour Choices et placeholder
    function updateChoices(choices, choicesArray, placeholderText) {
        if (!choices || typeof choices.setChoices !== 'function') {
            console.warn('Choices instance invalid');
            return;
        }
        
        console.log('Updating choices with', choicesArray.length, 'options');
        choices.setChoices(choicesArray, 'value', 'label', true);
        
        if (typeof choices.enable === 'function') {
            choices.enable();
        }
        
        const input = choices.passedElement.element.querySelector('input.choices__input');
        if (input) {
            input.placeholder = placeholderText;
        }
    }

    // Expose la fonction globalement pour appel depuis create_post.js et autres
    window.initAdvancedLocationSelector = initAdvancedLocationSelector;
})();

<< global_socket.js >>:  
// static/js/global_socket.js
// IMPORTANT : Ce script doit être chargé sur TOUTES les pages (dans base.html)

document.addEventListener('DOMContentLoaded', () => {
    // On vérifie si l'utilisateur est connecté avant d'ouvrir un socket
    const isLoggedIn = document.cookie.includes('access_token_cookie');

    if (isLoggedIn) {
        const socket = io();

        socket.on('connect', () => {
            console.log('Socket global connecté.');
        });

        /**
         * C'est le listener CLÉ pour le statut "délivré".
         * Il écoute les messages envoyés à la room personnelle de l'utilisateur.
         * * CORRECTION : La logique serveur (on_new_message) garantit déjà
         * que cet événement n'est émis que pour les destinataires.
         * Nous n'avons plus besoin de vérifier l'ID de l'expéditeur ici.
         */
        socket.on('new_message', (msg) => {
            // On accuse simplement réception du message
            socket.emit('message_delivered', { message_id: msg.id });
        });

        /**
         * Gère les notifications en temps réel (la cloche)
         */
        socket.on('new_notification', (data) => {
            console.log('Nouvelle notification:', data.message);
            // Ici, tu peux ajouter la logique pour afficher un "toast"
            // ou simplement mettre à jour le compteur
        });

        socket.on('notification_count_update', (data) => {
            console.log('Mise à jour compteur notif:', data.unread_count);
            const badge = document.getElementById('notification-badge-global');
            if (badge) {
                if (data.unread_count > 0) {
                    badge.textContent = data.unread_count;
                    badge.style.display = 'flex';
                } else {
                    badge.style.display = 'none';
                }
            }
        });

        socket.on('disconnect', () => {
            console.log('Socket global déconnecté.');
        });
    }
});

<< guest_nav.js >>:  
// static/js/guest_nav.js

document.addEventListener('DOMContentLoaded', () => {
    // --- Gestion de la modale "À propos" ---
    const aboutButton = document.getElementById('about-button');
    const aboutModal = document.getElementById('about-modal');

    if (aboutButton && aboutModal) {
        const closeModalBtn = aboutModal.querySelector('.close-modal-btn');

        aboutButton.addEventListener('click', () => {
            aboutModal.classList.remove('hidden');
        });

        closeModalBtn.addEventListener('click', () => {
            aboutModal.classList.add('hidden');
        });

        aboutModal.addEventListener('click', (e) => {
            if (e.target === aboutModal) {
                aboutModal.classList.add('hidden');
            }
        });
    }

    // --- Gestion du menu de langue ---
    const langMenuButton = document.querySelector('.language-menu-button');
    const langMenuDropdown = document.querySelector('.language-menu-dropdown');
    const langSelectors = document.querySelectorAll('.lang-selector');

    if (langMenuButton && langMenuDropdown) {
        langMenuButton.addEventListener('click', (e) => {
            e.stopPropagation();
            langMenuDropdown.classList.toggle('active');
        });

        document.addEventListener('click', () => {
            if (langMenuDropdown.classList.contains('active')) {
                langMenuDropdown.classList.remove('active');
            }
        });
    }

    if (langSelectors) {
        langSelectors.forEach(selector => {
            selector.addEventListener('click', async (e) => {
                e.preventDefault();
                const lang = e.target.dataset.lang;
                
                // Crée un formulaire en mémoire pour envoyer la langue
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/select-language';

                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'language';
                input.value = lang;
                form.appendChild(input);

                document.body.appendChild(form);
                form.submit();
            });
        });
    }
});

<< header_search.js >>:  
// DANS static/js/header_search.js

document.addEventListener('DOMContentLoaded', () => {
    const searchIconButton = document.getElementById('search-icon-btn');

    if (searchIconButton) {
        searchIconButton.addEventListener('click', (event) => {
            // Empêche le menu de se dérouler ou toute autre action par défaut
            event.preventDefault(); 
            // *** LA LIGNE MAGIQUE À AJOUTER ***
            event.stopPropagation(); // Empêche l'événement de "remonter" et d'activer d'autres menus
            
            // Si on est déjà sur la page des annonces...
            if (window.location.pathname === '/posts') {
                // ...on donne simplement le focus au champ de recherche de la page.
                document.getElementById('search-input')?.focus();
            } else {
                // Sinon, on redirige vers la page des annonces avec le paramètre magique.
                window.location.href = '/posts?focus_search=true';
            }
        });
    }
});

<< home.js >>:  
// static/js/home.js (Version avec redirection)

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const container = document.getElementById('posts-list-container');

    // On transforme la barre de recherche en bouton de redirection
    if (searchInput) {
        // On écoute le 'focus' qui est plus universel que le clic pour un input
        searchInput.addEventListener('focus', (event) => {
            // On empêche le clavier d'apparaître sur mobile inutilement
            event.target.blur(); 
            // On redirige vers la page des annonces avec un paramètre spécial
            window.location.href = '/posts?focus_search=true';
        });
    }

    // La logique pour les favoris reste la même
    if (container) {
        container.addEventListener('click', async (event) => {
            const favoriteBtn = event.target.closest('.favorite-btn');
            if (favoriteBtn) {
                event.preventDefault(); 
                const postId = favoriteBtn.dataset.postId;
                toggleFavorite(postId, favoriteBtn);
            }
        });
    }
});

async function toggleFavorite(postId, buttonElement) {
    const csrfToken = window.getCsrfToken();
    if (!csrfToken) {
        window.location.href = '/login';
        return;
    }
    try {
        const response = await fetch(`/api/posts/${postId}/favorite`, {
            method: 'POST',
            headers: { 'X-CSRF-TOKEN': csrfToken }
        });
        const data = await response.json();
        if (data.success) {
            buttonElement.classList.toggle('favorited', data.status === 'added');
        }
    } catch (error) {
        console.error(_("Error adding/removing favorite:"), error);
    }
}

<< login.js >>:  
// static/js/login.js (Version corrigée pour la connexion par e-mail)

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            // On récupère la valeur du champ e-mail
            const email = loginForm.email.value;
            const password = loginForm.password.value;

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    // On envoie l'e-mail et le mot de passe au serveur
                    body: JSON.stringify({ email: email, password: password })
                });

                const data = await response.json();

                if (data.success) {
                    // Si la connexion réussit, on redirige vers la page d'accueil
                    window.location.href = '/';
                } else {
                    // Sinon, on affiche le message d'erreur
                    displayMessage(data.message, 'error');
                }
            } catch (error) {
                console.error('Login error:', error);
                displayMessage(_('A network error occurred.'), 'error');
            }
        });
    }
});

<< messages.js >>:  
// static/js/messages.js (Version fusionnée et mise à jour - 21/10/2025)
document.addEventListener('DOMContentLoaded', async () => {
    
    const chatContainer = document.querySelector('.chat-container');
    if (!chatContainer) return; // Sécurité si on n'est pas sur la bonne page

    // Variables de l'original (gardées)
    let currentUserId = localStorage.getItem('user_id');

    if (!currentUserId) {
        try {
            const response = await fetch('/api/user');
            const data = await response.json();
            if (data.success && data.user) {
                currentUserId = data.user.id;
                localStorage.setItem('user_id', currentUserId);
            } else {
                chatContainer.innerHTML = `<p style="padding: 2rem; text-align: center;">${_("Please log in to see your messages.")}</p>`;
                return;
            }
        } catch (error) {
            return;
        }
    }

    const socket = io();
    let currentChatroomId = null, otherParticipant = null, replyContext = null;
    
    // Variables de l'original (gardées pour la voix)
    let mediaRecorder, audioChunks = [], isRecording = false, timerInterval, seconds = 0;
    let audioContext, analyser, sourceNode, animationFrameId;
    let stream; 
    
    // Variables du nouveau code (modifiées)
    let typingTimer; // 'isTyping' a été enlevé par le nouveau code
    let selectionMode = false;
    const selectedMessages = new Set();
    
    // --- NOUVEAU : Gestion de l'historique de navigation pour le bouton "retour" ---
    window.addEventListener('popstate', (event) => {
        if (chatContainer.classList.contains('chat-view-active')) {
            // Si on est dans une discussion, le "retour" nous ramène à la liste
            event.preventDefault();
            exitChatView();
        }
    });

    const dom = {
        chatContainer,
        messageInputArea: document.getElementById('message-input-area'),
        chatroomsList: document.getElementById('chatrooms-list'),
        welcomeScreen: document.getElementById('chat-welcome-screen'),
        mainScreen: document.getElementById('chat-main-screen'),
        chatHeader: document.getElementById('current-chat-header'),
        messagesDisplay: document.getElementById('messages-display'),
        messageInput: document.getElementById('message-input'),
        micOrSendBtn: document.getElementById('mic-or-send-btn'),
        attachFileButton: document.getElementById('attach-file-button'),
        fileInput: document.getElementById('file-input'), // Gardé (même si le nouveau code ne l'utilise pas directement)
        cancelVoiceBtn: document.getElementById('cancel-voice-btn'),
        pauseResumeBtn: document.getElementById('pause-resume-btn'),
        voiceSendBtn: document.getElementById('voice-send-btn'),
        replyPreview: document.getElementById('reply-preview-container'),
        cancelReplyBtn: document.getElementById('cancel-reply-btn'),
        ratingModal: document.getElementById('rating-modal'),
        ratingForm: document.getElementById('rating-form'),
        // NOUVEAU: Éléments pour l'upload et les émojis (gardés de l'original)
        attachmentPopup: document.getElementById('attachment-popup'),
        galleryInput: document.getElementById('gallery-input'),
        cameraInput: document.getElementById('camera-input'),
        documentInput: document.getElementById('document-input'),
        emojiButton: document.getElementById('emoji-button'),
    };
    let emojiPickerVisible = false;
    let attachmentPopupVisible = false;


    // --- NOUVELLES FONCTIONS DE SÉLECTION (du nouveau code) ---
    function enterSelectionMode(messageId, wrapper) {
        selectionMode = true;
        dom.chatContainer.classList.add('selection-mode');
        toggleMessageSelection(messageId, wrapper); // Sélectionne le premier
    }

    function exitSelectionMode() {
        selectionMode = false;
        selectedMessages.clear();
        dom.chatContainer.classList.remove('selection-mode');
        dom.messagesDisplay.querySelectorAll('.message-wrapper.selected').forEach(el => el.classList.remove('selected'));
        updateHeaderForSelection(); // Appel de la nouvelle fonction
    }

    function toggleMessageSelection(messageId, wrapper) {
        if (selectedMessages.has(messageId)) {
            selectedMessages.delete(messageId);
            wrapper.classList.remove('selected');
        } else {
            selectedMessages.add(messageId);
            wrapper.classList.add('selected');
        }
        if (selectedMessages.size === 0) {
            exitSelectionMode();
        } else {
            updateHeaderForSelection();
        }
    }
    function formatLocalDateTime(isoString) {
    if (!isoString) return '';
    // Assure-toi que la chaîne est bien en UTC si 'Z' manque (sécurité)
    if (!isoString.endsWith('Z')) isoString += 'Z';
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return ''; // Gestion d'erreur si la date est invalide

    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${hours}:${minutes}`;
}
    
    function updateHeaderForSelection() {
        if (!selectionMode) {
            if(otherParticipant) updateChatHeader(otherParticipant);
            return;
        }
        const count = selectedMessages.size;
        const canDelete = Array.from(selectedMessages).every(id => {
            const msgEl = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${id}']`);
            return msgEl && msgEl.classList.contains('sent');
        });

        dom.chatHeader.innerHTML = `
            <button class="chat-icon-button" id="cancel-selection-btn"><i class="fa-solid fa-times"></i></button>
            <strong class="selection-count">${count}</strong>
            <div class="selection-actions">
                <button class="chat-icon-button" id="copy-selection-btn" ${count !== 1 ? 'disabled' : ''}><i class="fa-solid fa-copy"></i></button>
                <button class="chat-icon-button" id="delete-selection-btn" ${!canDelete ? 'disabled' : ''}><i class="fa-solid fa-trash"></i></button>
            </div>
        `;
        addHeaderEventListeners();
    }

    // --- FONCTIONS DE MESSAGERIE (NOUVELLES du nouveau code) ---
    // Les fonctions addLocalMessage, updateLocalMessage, markAsFailed, retrySend, sendMessageLogic
    // ont été remplacées par cette nouvelle logique plus directe.

    function sendTextMessage() {
        const content = dom.messageInput.value.trim();
        if (!content && !replyContext) return; // Modifié: on peut envoyer une réponse sans texte
        
        const repliedToId = replyContext ? replyContext.messageId : null;
        // --- NOUVEAU : On récupère le contexte complet de la réponse pour l'affichage instantané ---
        const repliedToContext = replyContext;

        const tempId = 'temp-' + Date.now();
        displayMessageBubble({
            id: tempId,
            chatroom_id: currentChatroomId,
            sender_id: currentUserId,
            sender_username: _('Me'), // Corrigé de 'Me'
            content: content,
            timestamp: new Date().toISOString(),
            status: 'pending',
            replied_to: repliedToContext ? { id: repliedToId, content: repliedToContext.text, sender_username: repliedToContext.author } : null
        });
        scrollToBottom();

        socket.emit('new_message', {
            chatroom_id: currentChatroomId,
            content: content,
            replied_to_id: repliedToId
        }, (response) => {
            if (response && response.success) {
                // Utilise la nouvelle fonction de mise à jour
                updateMessageStatus(tempId, response.message_id, response.status);
            }
            // Note: Le nouveau code n'a pas de 'markAsFailed'
        });

        dom.messageInput.value = '';
        dom.messageInput.style.height = 'auto';
        hideReplyPreview();
        backToMicButton();
    }

    async function uploadAndSendFiles(files) {
        hideAllPopups();
        for (const file of files) {
            const formData = new FormData();
            
            // Logique de renommage de fichier de l'original (fusionnée)
            let filename = "file_upload";
            if (file.type && file.type.startsWith('audio/')) {
                const extension = file.type.split('/')[1].split(';')[0]; 
                filename = `voix.${extension}`;
            } else if (file.name) {
                filename = file.name;
            }
            formData.append('file', file, filename); 
            
            const tempId = 'temp-file-' + Date.now() + file.name;
            const fileURL = URL.createObjectURL(file); // Crée une URL locale pour l'aperçu

            displayMessageBubble({
                id: tempId,
                chatroom_id: currentChatroomId,
                sender_id: currentUserId,
                sender_username: _('Me'), // Corrigé de 'Me'
                file_url: fileURL,
                file_type: file.type,
                timestamp: new Date().toISOString(),
                status: 'pending',
                replied_to: replyContext ? { id: replyContext.messageId, content: replyContext.text, sender_username: replyContext.author } : null
            });
            scrollToBottom();
            
            const repliedToId = replyContext ? replyContext.messageId : null;
            hideReplyPreview(); // Cache l'aperçu après l'avoir utilisé

            try {
                const response = await fetch('/api/chat/upload', {
                    method: 'POST',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: formData
                });
                const data = await response.json();
                if (!data.success) throw new Error(data.message);

                socket.emit('new_message', {
                    chatroom_id: currentChatroomId,
                    file_path: data.file_path, // le nouveau code utilise file_path
                    file_type: data.file_type, // le nouveau code utilise file_type
                    replied_to_id: repliedToId
                }, (response) => {
                    if (response && response.success) {
                        // Met à jour l'ID et le statut, et potentiellement l'URL si le serveur la renvoie
                        updateMessageStatus(tempId, response.message_id, response.status, response.file_url || null);
                    }
                });

            } catch (error) {
                console.error("Upload error:", error);
                // Note: Le nouveau code n'a pas de 'markAsFailed'
            }
        }
    }

    // --- Fonctions de gestion des conversations (NOUVELLES du nouveau code) ---
    async function loadChatrooms() {
        try {
            const response = await fetch('/api/chat/chatrooms');
            const data = await response.json();
            if (data.success) {
                renderChatrooms(data.chatrooms);
                // Garde la logique de l'original
                checkForInitialChatroom(data.chatrooms);
            }
        } catch (error) { console.error(_('Error loading conversations:'), error); }
    }

    // DANS messages.js (à ajouter après la fonction loadChatrooms)

async function deleteChatroom(chatroomId) {
        if (!confirm(_("Are you sure you want to delete this conversation? This action is irreversible."))) {
            return;
        }

        try {
            const response = await fetch(`/api/chat/chatroom/${chatroomId}`, {
                method: 'DELETE',
                headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } // Assure-toi que getCsrfToken existe
            });
            const data = await response.json();
            if (data.success) {
                // Supprimer la conversation de l'interface
                const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${chatroomId}"]`);
                if (chatItem) {
                    chatItem.remove();
                }
                // Si c'était la conversation active, on retourne à l'accueil
                if (currentChatroomId === chatroomId) {
                    exitChatView();
                }
            } else {
                alert(data.message || _("Error during deletion."));
            }
        } catch (error) {
            console.error("Delete chat error:", error);
            alert(_("A network error has occurred."));
        }
    }


// DANS : messages.js
// REMPLACEZ l'ancienne fonction renderChatrooms par celle-ci :

function renderChatrooms(chatrooms) {
    if (!dom.chatroomsList) return; // Gardé de l'original
    dom.chatroomsList.innerHTML = '';
    if (chatrooms.length === 0) {
        dom.chatroomsList.innerHTML = `<p class="empty-list-message">${_("No conversation.")}</p>`;
        return;
    }
    chatrooms.forEach(room => {
        const otherP = room.other_participant; // Raccourci du nouveau code
        if (!otherP) return;

        let avatarHTML = otherP.profile_photo
            ? `<img src="${otherP.profile_photo}" alt="${otherP.username}" class="avatar-img">`
            : `<div class="chat-item-avatar">${otherP.username.charAt(0).toUpperCase()}</div>`;
        
        // NOUVEAU: Titre de l'annonce
        const postTitleHTML = room.post_info ? `<span class="chat-item-post-title">${room.post_info.title}</span>` : '';

        let lastMsgContent = `<em>${_("Start the conversation!")}</em>`;
        let statusIcon = ''; // Gardé de l'original
        let lastMsgTime = ''; // Gardé de l'original

        if (room.last_message) {
            if (room.last_message.content) lastMsgContent = room.last_message.content;
            else if (room.last_message.file_type?.startsWith('image')) lastMsgContent = `📷 ${_('Photo')}`;
            else if (room.last_message.file_type?.startsWith('audio')) lastMsgContent = `🎤 ${_('Voice message')}`;
            else if (room.last_message.file_type?.startsWith('video')) lastMsgContent = `📹 ${_('Video')}`; // Ajout du nouveau code
            else lastMsgContent = `📎 ${_('Attached file')}`;
            
            // Logique de temps de l'original (gardée)
            let lastMsgTimestamp = room.last_message.timestamp;
            if (!lastMsgTimestamp.endsWith('Z')) lastMsgTimestamp += 'Z';
            const parsedDate = new Date(lastMsgTimestamp);
            lastMsgTime = formatLocalDateTime(lastMsgTimestamp);

            // Logique d'icône de statut de l'original (gardée)
            if (String(room.last_message.sender_id) === String(currentUserId)) {
                const statusClass = room.last_message.status === 'read' ? 'read' : 'sent';
                const iconClass = room.last_message.status === 'sent' ? 'fa-solid fa-check' : 'fa-solid fa-check-double';
                statusIcon = `<i class="chat-status-icon ${statusClass} ${iconClass}"></i>`;
            }
        }
        const roomDiv = document.createElement('div');
    roomDiv.className = 'chat-list-item';
    roomDiv.dataset.chatroomId = room.id;
    
    // =================================================================
    // --- MODIFICATION 1 : Remplacement du Menu par un Bouton Simple ---
    // =================================================================
    // L'ancien HTML avec le menu déroulant a été remplacé par ce bouton unique.
    roomDiv.innerHTML = `
        ${avatarHTML}
        <div class="chat-item-main">
            <div class="chat-item-top-row">
                <strong>${otherP.username}</strong>
                <span class="chat-item-time">${lastMsgTime}</span>
            </div>
            ${postTitleHTML} 
            <div class="chat-item-bottom-row">
                <p class="last-message-preview">${statusIcon}${lastMsgContent}</p> 
                ${room.unread_count > 0 ? `<div class="notification-badge">${room.unread_count}</div>` : ''}
            </div>
        </div>
         <div class="chatroom-actions">
             <button class="chat-icon-button delete-chatroom-btn" title="${_('Delete conversation')}" data-chatroom-id="${room.id}">
                <i class="fa-solid fa-trash"></i>
             </button>
         </div>
    `;

    roomDiv.addEventListener('click', (e) => {
            const deleteButton = e.target.closest('.delete-chatroom-btn');

            // Cas 1 : Clic sur le bouton "Supprimer"
            if (deleteButton) {
                e.stopPropagation(); // Empêche d'entrer dans la conversation
                const chatroomId = Number(deleteButton.dataset.chatroomId);
                deleteChatroom(chatroomId); // Appelle directly la suppression

            // Cas 2 : Clic sur l'item pour ouvrir la conversation
            } else if (!e.target.closest('.chatroom-actions')) {
                joinChatroom(room.id, otherP);
            }
        });

        dom.chatroomsList.appendChild(roomDiv);
    });
}
    function updateChatListItem(msg) {
        if (!dom.chatroomsList) return;

        const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${msg.chatroom_id}"]`);
        if (!chatItem) return; // Si la conversation n'est pas dans la liste

        // Mise à jour du dernier message
        const lastMsgPreview = chatItem.querySelector('.last-message-preview');
        if (lastMsgPreview) {
            let lastMsgContent = '';
            if (msg.content) lastMsgContent = msg.content;
            else if (msg.file_type?.startsWith('image')) lastMsgContent = `📷 ${_('Photo')}`;
            else if (msg.file_type?.startsWith('audio')) lastMsgContent = `🎤 ${_('Voice message')}`;
            else if (msg.file_type?.startsWith('video')) lastMsgContent = `📹 ${_('Video')}`;
            else lastMsgContent = `📎 ${_('Attached file')}`;
            
            // On ajoute l'icône de statut si c'est notre message
            let statusIconHTML = '';
            if (String(msg.sender_id) === String(currentUserId)) {
                const iconClass = (msg.status === 'delivered' || msg.status === 'read') ? 'fa-solid fa-check-double' : 'fa-solid fa-check';
                statusIconHTML = `<i class="chat-status-icon ${msg.status} ${iconClass}"></i>`;
            }
            lastMsgPreview.innerHTML = `${statusIconHTML}${lastMsgContent}`;
        }

        // Mise à jour de l'heure
        const timeEl = chatItem.querySelector('.chat-item-time');
        if (timeEl) {
            timeEl.textContent = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }

        // Mettre la conversation en haut de la liste
        dom.chatroomsList.prepend(chatItem);
    }

    // --- Fonctions de gestion de la vue de discussion (NOUVELLES du nouveau code) ---
    function joinChatroom(chatroomId, participantData) {
        if (!participantData) return;
        // La vérification 'if (currentChatroomId === chatroomId ...)' a été retirée par le nouveau code
        
        // NOUVEAU : Gère l'historique du navigateur
        // Modifié pour ne pas ajouter si c'est déjà le bon
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('chatroom_id') !== chatroomId) {
            history.pushState({ chatroomId: chatroomId }, `Chat with ${participantData.username}`, `?chatroom_id=${chatroomId}`);
        }
        
        document.body.classList.add('in-chat-view');
        dom.chatContainer.classList.add('chat-view-active');
        exitSelectionMode(); // Gardé de l'original

        otherParticipant = participantData;
        currentChatroomId = chatroomId;
        socket.emit('join', { chatroom_id: chatroomId });

        document.querySelectorAll('.chat-list-item').forEach(item => item.classList.remove('active'));
        const activeItem = document.querySelector(`.chat-list-item[data-chatroom-id="${chatroomId}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
            activeItem.querySelector('.notification-badge')?.remove();
        }
        
        updateChatHeader(participantData);

        dom.welcomeScreen.classList.add('hidden'); // Gardé de l'original
        dom.mainScreen.classList.remove('hidden'); // Gardé de l'original
        // NOUVEAU: Spinner de chargement
        dom.messagesDisplay.innerHTML = `<div class="spinner-container"><div class="spinner"></div></div>`;
        
        dom.messageInput.value = ''; // Gardé de l'original
        backToMicButton(); // Gardé de l'original
    }

    // NOUVELLE FONCTION du nouveau code
    function exitChatView() {
        document.body.classList.remove('in-chat-view');
        dom.chatContainer.classList.remove('chat-view-active');
        currentChatroomId = null;
        otherParticipant = null;
        exitSelectionMode();
        // Gère l'historique
        history.pushState({ chatroomId: null }, 'Messages', '/messages');
        
        // Remet l'écran d'accueil (logique de l'original)
        document.querySelectorAll('.chat-list-item').forEach(item => item.classList.remove('active'));
        dom.mainScreen.classList.add('hidden');
        dom.welcomeScreen.classList.remove('hidden');
    }

    // NOUVELLE FONCTION du nouveau code
    function updateChatHeader(participantData) {
        let avatarHTML = participantData.profile_photo
            ? `<img src="${participantData.profile_photo}" alt="${participantData.username}" class="avatar-img">`
            : `<div class="chat-item-avatar">${participantData.username.charAt(0).toUpperCase()}</div>`;

        dom.chatHeader.innerHTML = `
            <button class="back-to-list-btn chat-icon-button"><i class="fa-solid fa-arrow-left"></i></button>
            <div class="chat-header-info">${avatarHTML}<div class="chat-header-text"><strong>${participantData.username}</strong><div id="activity-indicator"></div></div></div>
            <div class="chat-header-actions"><button class="rate-user-btn chat-icon-button" title="${_('Rate')}"><i class="fa-solid fa-star"></i></button></div>
        `;
        addHeaderEventListeners();
    }

    // NOUVELLE FONCTION du nouveau code (fusionne l'ancienne)
    function addHeaderEventListeners() {
        // Nouveau : utilise window.history.back() pour le bouton retour
        dom.chatHeader.querySelector('.back-to-list-btn')?.addEventListener('click', () => window.history.back());
        
        // Gardé : le bouton de notation
        dom.chatHeader.querySelector('.rate-user-btn')?.addEventListener('click', openRatingModal);
        
        // Nouveau : actions de sélection
        dom.chatHeader.querySelector('#cancel-selection-btn')?.addEventListener('click', exitSelectionMode);
        dom.chatHeader.querySelector('#copy-selection-btn')?.addEventListener('click', copySelectedMessages);
        dom.chatHeader.querySelector('#delete-selection-btn')?.addEventListener('click', deleteSelectedMessages);
    }

    
    function insertDateSeparatorIfNeeded(currentMessageTimestamp, lastMessageTimestamp) {
        // Si c'est le premier message, pas de séparateur avant
        if (!lastMessageTimestamp) return;

        const currentDate = new Date(currentMessageTimestamp);
        const lastDate = new Date(lastMessageTimestamp);

        // On compare uniquement le jour, le mois et l'année, pas l'heure
        if (currentDate.toDateString() !== lastDate.toDateString()) {
            const separator = document.createElement('div');
            separator.className = 'date-separator';
            
            const today = new Date();
            const yesterday = new Date();
            yesterday.setDate(today.getDate() - 1);
            
            let dateText = '';
            if (currentDate.toDateString() === today.toDateString()) {
                dateText = _('Today');
            } else if (currentDate.toDateString() === yesterday.toDateString()) {
                dateText = _('Yesterday');
            } else {
                // Format de date plus complet pour les jours plus anciens
                dateText = currentDate.toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
            }

            separator.innerHTML = `<span>${dateText}</span>`;
            dom.messagesDisplay.appendChild(separator);
        }
    }
    function displayMessageBubble(msg, lastMessageTimestamp = null) {
        // On insère le séparateur de date si nécessaire (pour la requête 2)
        insertDateSeparatorIfNeeded(msg.timestamp, lastMessageTimestamp);

        const isSentByMe = String(msg.sender_id) === String(currentUserId);
        const wrapper = document.createElement('div');
        wrapper.className = `message-wrapper ${isSentByMe ? 'sent' : 'received'}`;
        wrapper.dataset.messageId = msg.id;
        // On stocke le timestamp pour la logique du séparateur de date
        wrapper.dataset.timestamp = msg.timestamp; 
        
        let replyHTML = '';
        if (msg.replied_to) {
            let replyContent = msg.replied_to.content || `<em>${_('Media')}</em>`;
            if (replyContent.length > 70) replyContent = replyContent.substring(0, 70) + '...';
            replyHTML = `<div class="quoted-message"><strong>${msg.replied_to.sender_username}</strong><p>${replyContent}</p></div>`;
        }

        let contentHTML = '';
        if (msg.file_url) {
            // ... (le reste de la logique de contenu reste identique à ton code original)
            const fileType = msg.file_type || '';
            if (fileType.startsWith('image/')) {
                contentHTML = `<div class="message-content image-container"><img src="${msg.file_url}" class="chat-image" onload="if(this.src.startsWith('blob:')) URL.revokeObjectURL(this.src)" onclick="window.open('${msg.file_url}', '_blank')"></div>`;
            } else if (fileType.startsWith('video/')) {
                contentHTML = `<div class="message-content video-container"><video src="${msg.file_url}" class="chat-video" controls onload="if(this.src.startsWith('blob:')) URL.revokeObjectURL(this.src)"></video></div>`;
            } else if (fileType.startsWith('audio/')) {
                contentHTML = `<div class="message-content audio-container"><audio controls class="chat-audio" src="${msg.file_url}" onload="if(this.src.startsWith('blob:')) URL.revokeObjectURL(this.src)"></audio></div>`;
            } else {
                const fileName = msg.file_url.split('/').pop().split('_').slice(1).join('_') || _('File');
                contentHTML += `<a href="${msg.file_url}" target="_blank" class="chat-file-link"><i class="fa-solid fa-file"></i><span>${fileName}</span></a>`;
            }
        }
        if (msg.content) {
            contentHTML += `<div class="message-content text-content"><p>${msg.content.replace(/\n/g, '<br>')}</p></div>`;
        }
        
        let statusHTML = '';
        if (isSentByMe) {
            const statusClass = msg.status === 'read' ? 'read' : '';
            const iconClass = msg.status === 'pending' ? 'fa-regular fa-clock' : (msg.status === 'sent' ? 'fa-solid fa-check' : 'fa-solid fa-check-double');
            statusHTML = `<span class="message-status ${statusClass}" data-status="${msg.status}"><i class="${iconClass}"></i></span>`;
        }

        const time = formatLocalDateTime(msg.timestamp);

        wrapper.innerHTML = `
            <div class="message-bubble-container">
                <div class="message-bubble">${replyHTML}${contentHTML}</div>
                <div class="message-meta"><span>${time}</span>${statusHTML}</div>
            </div>`;
        
        dom.messagesDisplay.appendChild(wrapper);

        // --- CORRECTION DES ÉCOUTEURS D'ÉVÉNEMENTS ---
        let pressTimer = null;

    wrapper.addEventListener('pointerdown', (e) => {
        // Empêche le menu contextuel par défaut sur ordinateur
        if (e.pointerType === 'mouse') e.preventDefault();
        
        // Démarre le minuteur pour l'appui long
        pressTimer = setTimeout(() => {
            enterSelectionMode(msg.id, wrapper);
            pressTimer = null; // Réinitialise le timer pour éviter les conflits
        }, 500); // 500ms pour un appui long
    });

    const clearPressTimer = () => {
        if (pressTimer) {
            clearTimeout(pressTimer);
        }
    };
    
    // Si on lève le doigt ou si le curseur quitte la zone, on annule l'appui long
    wrapper.addEventListener('pointerup', clearPressTimer);
    wrapper.addEventListener('pointerleave', clearPressTimer);

    // Gère le CLIC SIMPLE
    wrapper.addEventListener('click', () => {
        if (selectionMode) {
            // Si on est en mode sélection, le clic sert à ajouter/retirer
            toggleMessageSelection(msg.id, wrapper);
        } else {
            // Sinon, le clic sert à répondre (citer)
            const contentForReply = msg.content || (msg.file_type ? _('Media') : '');
            showReplyPreview(msg.id, msg.sender_username, contentForReply);
        }
    });
}

    // --- Fonctions de mise à jour et actions (NOUVELLES) ---
    function updateMessageStatus(tempId, newId, status, newUrl = null) {
        const wrapper = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${tempId}']`);
        if (!wrapper) return;

        wrapper.dataset.messageId = newId;
        const statusEl = wrapper.querySelector('.message-status');
        if (statusEl) {
            const icon = statusEl.querySelector('i');
            statusEl.dataset.status = status; // Ajouté
            statusEl.className = `message-status ${status}`;
            // Logique d'icône mise à jour
            icon.className = status === 'sent' ? 'fa-solid fa-check' : (status === 'delivered' || status === 'read' ? 'fa-solid fa-check-double' : 'fa-regular fa-clock');
        }
        if (newUrl) {
            const mediaEl = wrapper.querySelector('img, video, audio');
            if (mediaEl) {
                mediaEl.src = newUrl;
                // Met à jour le lien cliquable pour les images
                const imgLink = mediaEl.closest('.image-container');
                if (imgLink) imgLink.querySelector('img').setAttribute('onclick', `window.open('${newUrl}', '_blank')`);
            }
        }
    }
    
    function copySelectedMessages() {
    if (selectedMessages.size !== 1) return;
    const msgId = selectedMessages.values().next().value;
    const msgEl = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${msgId}'] .text-content p`);
    
    if (msgEl && msgEl.innerText) {
        navigator.clipboard.writeText(msgEl.innerText)
            .catch(err => {
                console.error('Failed to copy text: ', err);
                // On peut ajouter un message d'erreur discret si besoin, mais pas de succès
            });
    }
    // On quitte le mode sélection que la copie ait réussi ou non
    exitSelectionMode();
}

    function deleteSelectedMessages() {
        if (confirm(_('Delete messages?'))) {
            socket.emit('delete_multiple_messages', { message_ids: Array.from(selectedMessages) });
        }
    }

    // --- Fonctions de réponse (Gardées de l'original) ---
    function showReplyPreview(messageId, author, content, type) {
        replyContext = { messageId, author, text: content };
        const replyContentEl = dom.replyPreview.querySelector('.reply-preview-content');
        if (!replyContentEl) return;

        dom.replyPreview.classList.remove('hidden');
        dom.messageInput.focus();

        replyContentEl.innerHTML = `
            <div class="reply-preview-inner quoted-message">
                <strong>${author}</strong>
                <p>${content.length > 70 ? content.substring(0, 70) + '...' : content}</p>
            </div>
        `;
    }

    function hideReplyPreview() {
        replyContext = null;
        if (dom.replyPreview) {
            dom.replyPreview.classList.add('hidden');
            const content = dom.replyPreview.querySelector('.reply-preview-content');
            if (content) content.innerHTML = '';
        }
    }

    // --- Fonctions des messages vocaux (Gardées de l'original, sauf resetVoiceUI) ---
    function formatTime(totalSeconds) {
        const minutes = Math.floor(totalSeconds / 60);
        const secondsVal = Math.floor(totalSeconds % 60);
        return `${minutes}:${secondsVal.toString().padStart(2, '0')}`;
    }
    async function startRecording() {
        if (isRecording) return;
        // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
        try {
            stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
            document.querySelector('.input-mode-voice').classList.remove('hidden');
            isRecording = true;
            dom.messageInputArea.classList.add('recording-active');
            dom.messageInputArea.style.minHeight = '120px';
            
            seconds = 0;
            const timerEl = document.getElementById('record-timer');
            timerEl.textContent = '0:00';
            timerInterval = setInterval(() => {
                seconds++;
                timerEl.textContent = formatTime(seconds);
            }, 1000);
            
            audioChunks = [];
            mediaRecorder = new MediaRecorder(stream);
            mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
            mediaRecorder.onstop = () => {
                if (audioChunks.length > 0) {
                    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                    // Utilise la NOUVELLE fonction d'upload (pour un seul fichier)
                    uploadAndSendFiles([audioBlob]);
                }
            };

            audioContext = new (window.AudioContext || window.webkitAudioContext)();
            analyser = audioContext.createAnalyser();
            analyser.fftSize = 256;
            sourceNode = audioContext.createMediaStreamSource(stream);
            sourceNode.connect(analyser);
            
            mediaRecorder.start();
            drawWaveform();

        } catch (err) {
            console.error("Erreur d'enregistrement :", err);
            isRecording = false;
            dom.messageInputArea.classList.remove('recording-active');
            dom.messageInputArea.style.minHeight = 'var(--footer-height)';
        }
    }

    // NOUVELLE fonction resetVoiceUI (du nouveau code)
    function resetVoiceUI() {
        if(timerInterval) clearInterval(timerInterval); // Vérification ajoutée
        isRecording = false;
        if(animationFrameId) cancelAnimationFrame(animationFrameId); // Vérification ajoutée
        if (audioContext) audioContext.close();
        if (stream) { stream.getTracks().forEach(track => track.stop()); }
        
        // On s'assure de cacher l'UI vocale et de réinitialiser la hauteur
        document.querySelector('.input-mode-voice').classList.add('hidden');
        dom.messageInputArea.classList.remove('recording-active');
        dom.messageInput.style.height = 'auto'; // Réinitialise la hauteur du textarea
        handleInputChange(); // Ré-évalue s'il faut afficher le micro ou l'avion
        dom.messageInputArea.style.minHeight = 'var(--footer-height)'; // Ajouté pour forcer la réinitialisation
    }


    function stopAndSendRecording() {
        if (!isRecording || !mediaRecorder) return;
        // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
        mediaRecorder.stop();
        resetVoiceUI();
    }

    function cancelRecording() {
        if (!isRecording || !mediaRecorder) return;
        // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
        mediaRecorder.onstop = null;
        mediaRecorder.stop();
        resetVoiceUI();
    }

    function pauseOrResumeRecording() {
        if (!isRecording || !mediaRecorder) return;
        const pauseBtnIcon = dom.pauseResumeBtn?.querySelector('i');
        if (!pauseBtnIcon) return;

        if (mediaRecorder.state === 'recording') {
            mediaRecorder.pause();
            clearInterval(timerInterval);
            cancelAnimationFrame(animationFrameId);
            pauseBtnIcon.classList.remove('fa-pause');
            pauseBtnIcon.classList.add('fa-play');
        } else if (mediaRecorder.state === 'paused') {
            mediaRecorder.resume();
            const timerEl = document.getElementById('record-timer');
            timerInterval = setInterval(() => {
                seconds++;
                timerEl.textContent = formatTime(seconds);
            }, 1000);
            drawWaveform(); 
            pauseBtnIcon.classList.remove('fa-play');
            pauseBtnIcon.classList.add('fa-pause');
        }
    }

    function drawWaveform() {
        animationFrameId = requestAnimationFrame(drawWaveform);
        const dataArray = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteFrequencyData(dataArray);

        const waveformContainer = document.getElementById('waveform-container');
        if (!waveformContainer) return;
        waveformContainer.innerHTML = ''; 

        const barCount = 30; 

        for (let i = 0; i < barCount; i++) {
            const barHeight = Math.pow(dataArray[i * 2] / 255, 2) * 100;
            const bar = document.createElement('div');
            bar.className = 'waveform-bar';
            bar.style.height = `${Math.max(5, barHeight)}%`;
            waveformContainer.appendChild(bar);
        }
    }
    
    // --- Fonctions de notation (Gardées de l'original) ---
    function openRatingModal() {
        if (!otherParticipant || !dom.ratingModal) {
            console.error("ERREUR : La modale ne peut s'ouvrir. 'otherParticipant' ou 'dom.ratingModal' est manquant.");
            return;
        }
        const ratedUsernameEl = dom.ratingModal.querySelector('#rated-username');
        if (ratedUsernameEl) {
            ratedUsernameEl.textContent = otherParticipant.username;
        }
        dom.ratingModal.classList.remove('hidden');
    }
    
    function closeRatingModal() { if(dom.ratingModal) dom.ratingModal.classList.add('hidden'); }
    
    async function handleRatingSubmit(e) {
        e.preventDefault();
        const stars = dom.ratingModal.querySelector('#rating-value').value;
        if (stars === '0') { alert(_('Please select a rating.')); return; }
        try {
            const response = await fetch(`/api/users/${otherParticipant.id}/rate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify({ stars: parseInt(stars), comment: e.target.comment.value })
            });
            const data = await response.json();
            alert(data.message);
            if(data.success) closeRatingModal();
        } catch(err) { console.error(_("Rating error:"), err); }
    }
    
    function handleStarHover(e) {
        const stars = dom.ratingModal.querySelectorAll('.star-rating .star');
        const hoverValue = e.target.dataset.value;
        stars.forEach(s => { s.textContent = s.dataset.value <= hoverValue ? '★' : '☆'; });
    }
    
    function resetStarHover() {
        const stars = dom.ratingModal.querySelectorAll('.star-rating .star');
        const currentValue = dom.ratingModal.querySelector('#rating-value').value;
        stars.forEach(s => { s.textContent = s.dataset.value <= currentValue ? '★' : '☆'; });
    }
    
    function handleStarClick(e) {
        dom.ratingModal.querySelector('#rating-value').value = e.target.dataset.value;
        resetStarHover();
    }

    // --- Fonctions utilitaires (Gardées de l'original) ---
    function scrollToBottom(instant = false) { // Paramètre 'instant' ajouté
        setTimeout(() => {
            if (dom.messagesDisplay) dom.messagesDisplay.scrollTo({ 
                top: dom.messagesDisplay.scrollHeight, 
                behavior: instant ? 'auto' : 'smooth' // 'auto' pour instantané
            });
        }, 100);
    }

    function checkForInitialChatroom(chatrooms) {
        const urlParams = new URLSearchParams(window.location.search);
        const initialChatroomId = urlParams.get('chatroom_id');
        if (initialChatroomId && chatrooms.some(c => c.id == initialChatroomId)) {
             const roomToJoin = chatrooms.find(c => c.id == initialChatroomId);
             if (roomToJoin) joinChatroom(roomToJoin.id, roomToJoin.other_participant);
             // La ligne 'window.history.replaceState' a été retirée, gérée par le 'popstate'
        }
    }
    
    function handleInputChange() {
        const text = dom.messageInput.value;
        const isRecordingActive = dom.messageInputArea.classList.contains('recording-active');

        if (text.trim() !== '' && !isRecordingActive) {
            switchToSendButton();
        } else if (!isRecordingActive) {
            backToMicButton();
        }

        const textarea = dom.messageInput;
        textarea.style.height = 'auto'; 
        textarea.style.height = `${textarea.scrollHeight}px`;
    }
    function switchToSendButton() {
        dom.micOrSendBtn.classList.remove('mic-mode');
        dom.micOrSendBtn.classList.add('send-mode');
        dom.micOrSendBtn.innerHTML = `<i class="fa-solid fa-paper-plane"></i>`;
    }

    function backToMicButton() {
        dom.micOrSendBtn.classList.remove('send-mode');
        dom.micOrSendBtn.classList.add('mic-mode');
        dom.micOrSendBtn.innerHTML = `<i class="fa-solid fa-microphone"></i>`;
    }
    
    // --- Fonctions d'Upload et Popups (Gardées de l'original) ---
    function handleAttachmentClick(e) {
        const action = e.currentTarget.dataset.action;
        switch (action) {
            case 'gallery': dom.galleryInput.click(); break;
            case 'camera': dom.cameraInput.click(); break;
            case 'document': dom.documentInput.click(); break;
        }
        dom.attachmentPopup.classList.remove('active');
    }
    
    function hideAllPopups() {
        if (attachmentPopupVisible) {
            dom.attachmentPopup.classList.remove('active');
            attachmentPopupVisible = false;
        }
        if (emojiPickerVisible) {
            const picker = document.querySelector('emoji-picker');
            if(picker) picker.classList.remove('visible');
            
            document.body.classList.remove('emoji-picker-active'); // Modifié (original)
            
            const emojiIcon = dom.emojiButton.querySelector('i');
            emojiIcon.classList.remove('fa-keyboard');
            emojiIcon.classList.add('fa-smile');
            emojiPickerVisible = false;
        }
    }


document.addEventListener('click', (e) => {
    // Si le clic n'est pas sur un bouton d'action ou dans un menu...
    if (!e.target.closest('.more-actions-btn') && !e.target.closest('.actions-dropdown')) {
        document.querySelectorAll('.actions-dropdown.visible').forEach(d => d.classList.remove('visible'));
    }
});
    if (dom.messageInput) {
        dom.messageInput.addEventListener('input', handleInputChange);
        dom.messageInput.addEventListener('keyup', handleInputChange);
        // L'écouteur pour 'isTyping' a été retiré par le nouveau code.
    }
    if (dom.micOrSendBtn) {
        dom.micOrSendBtn.addEventListener('click', () => {
            const hasText = dom.messageInput.value.trim().length > 0;
            const isRecordingActive = dom.messageInputArea.classList.contains('recording-active');
            if (isRecordingActive) stopAndSendRecording();
            else if (hasText) sendTextMessage();
            else startRecording();
        });
    }
    // Écouteurs vocaux (Gardés)
    if(dom.cancelVoiceBtn) dom.cancelVoiceBtn.addEventListener('click', cancelRecording);
    if(dom.voiceSendBtn) dom.voiceSendBtn.addEventListener('click', stopAndSendRecording);
    if(dom.cancelReplyBtn) dom.cancelReplyBtn.addEventListener('click', hideReplyPreview);
    if(dom.pauseResumeBtn) dom.pauseResumeBtn.addEventListener('click', pauseOrResumeRecording);
    
    
    if (dom.ratingModal) {
        const closeModalBtn = dom.ratingModal.querySelector('.close-modal-btn');
        if (closeModalBtn) closeModalBtn.addEventListener('click', closeRatingModal);
        dom.ratingModal.addEventListener('click', e => { if (e.target === dom.ratingModal) closeRatingModal(); });
        if (dom.ratingForm) dom.ratingForm.addEventListener('submit', handleRatingSubmit);
        const stars = dom.ratingModal.querySelectorAll('.star-rating .star');
        if (stars) {
            stars.forEach(star => {
                star.addEventListener('mouseover', handleStarHover);
                star.addEventListener('mouseout', resetStarHover);
                star.addEventListener('click', handleStarClick);
            });
        }
    }
    
    // Écouteurs des popups (Gardés)
    if(dom.attachFileButton) {
        dom.attachFileButton.addEventListener('click', (e) => {
            e.stopPropagation(); 
            if (emojiPickerVisible) {
                hideAllPopups();
            }
            attachmentPopupVisible = !dom.attachmentPopup.classList.contains('active');
            dom.attachmentPopup.classList.toggle('active', attachmentPopupVisible);
        });
    }
    if(dom.attachmentPopup) {
        dom.attachmentPopup.querySelectorAll('.attachment-option').forEach(btn => {
            btn.addEventListener('click', handleAttachmentClick);
        });
    }
    
    // NOUVEAU: Écouteurs pour les inputs de fichier (Mis à jour)
    // Ils utilisent tous la nouvelle fonction 'uploadAndSendFiles'
    if(dom.galleryInput) dom.galleryInput.addEventListener('change', (e) => { if(e.target.files.length > 0) uploadAndSendFiles(e.target.files); });
    if(dom.cameraInput) dom.cameraInput.addEventListener('change', (e) => { if(e.target.files.length > 0) uploadAndSendFiles(e.target.files); });
    if(dom.documentInput) dom.documentInput.addEventListener('change', (e) => { if(e.target.files.length > 0) uploadAndSendFiles(e.target.files); });

    // Écouteur Emoji (Gardé)
    if(dom.emojiButton) {
        dom.emojiButton.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (attachmentPopupVisible) hideAllPopups(); 

            let picker = document.querySelector('emoji-picker');
            if (!picker) {
                await import('https://cdn.jsdelivr.net/npm/emoji-picker-element@^1/index.js');
                picker = document.createElement('emoji-picker');
                document.body.appendChild(picker);
                picker.addEventListener('emoji-click', event => {
                    dom.messageInput.value += event.detail.unicode;
                    handleInputChange();
                });
            }

            emojiPickerVisible = !picker.classList.contains('visible');
            document.body.classList.toggle('emoji-picker-active', emojiPickerVisible);
            picker.classList.toggle('visible', emojiPickerVisible);

            const emojiIcon = dom.emojiButton.querySelector('i');
            if (emojiPickerVisible) {
                document.activeElement.blur();
                emojiIcon.classList.remove('fa-smile');
                emojiIcon.classList.add('fa-keyboard');
                scrollToBottom();
            } else {
                emojiIcon.classList.remove('fa-keyboard');
                emojiIcon.classList.add('fa-smile');
                dom.messageInput.focus();
            }
        });
    }
    
    // Écouteurs divers (Gardés)
    document.addEventListener('click', (e) => {
        if (!dom.attachmentPopup.contains(e.target) && !dom.attachFileButton.contains(e.target) &&
            !document.querySelector('emoji-picker')?.contains(e.target) && !dom.emojiButton.contains(e.target)) {
            hideAllPopups();
        }
    });
    
    if (dom.messageInput) {
        dom.messageInput.addEventListener('focus', () => {
            if (emojiPickerVisible) {
                dom.emojiButton.click();
            }
        });
    }
    
    // --- ÉVÉNEMENTS SOCKET.IO (NOUVEAU bloc du nouveau code) ---
    socket.on('connect', () => console.log(_('Socket.IO Connected.')));
    socket.on('message_history', (data) => {
        // 1. On vide le spinner
        dom.messagesDisplay.innerHTML = ''; 
        let lastTimestamp = null;

        // 2. On affiche chaque message de l'historique
        data.messages.forEach(msg => {
            displayMessageBubble(msg, lastTimestamp);
            lastTimestamp = msg.timestamp; // On met à jour pour le prochain tour
        });

        // 3. On défile en bas SANS animation (true = instantané)
        scrollToBottom(true); 
    });
    
// static/js/messages.js

socket.on('new_message', msg => {
    
    // 1. On ignore nos propres messages (correction précédente, inchangée)
    if (String(msg.sender_id) === String(currentUserId)) {
        const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${msg.chatroom_id}"]`);
        if (chatItem) { 
            updateChatListItem(msg); 
        } else { 
            loadChatrooms(); 
        }
        return; 
    }

    // --- Le code ci-dessous ne s'exécute que pour les messages REÇUS ---
    const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${msg.chatroom_id}"]`);

    // Si on est DANS la bonne conversation
    if (msg.chatroom_id === currentChatroomId) {
        const lastMessageEl = dom.messagesDisplay.querySelector('.message-wrapper:last-child');
        const lastTimestamp = lastMessageEl ? lastMessageEl.dataset.timestamp : null;
        
        displayMessageBubble(msg, lastTimestamp);
        scrollToBottom();

        // =================================================================
        // --- DÉBUT DE LA CORRECTION (STATUT 1/2) ---
        // Le message est affiché, donc il est 'lu'
        socket.emit('mark_as_read', { message_id: msg.id });
        // =================================================================

    } else {
        // =================================================================
        // --- DÉBUT DE LA CORRECTION (STATUT 2/2) ---
        // On n'est PAS dans la conversation. Le message est 'distribué'.
        socket.emit('message_delivered', { message_id: msg.id });
        // =================================================================
    }

    // Mise à jour de la liste de gauche (logique d'origine, inchangée)
    if (chatItem) {
        updateChatListItem(msg);
    } else {
        loadChatrooms();
    }
});
    
    socket.on('messages_deleted', (data) => {
        data.message_ids.forEach(id => {
            dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${id}']`)?.remove();
        });
        exitSelectionMode();
    });

    socket.on('message_status_updated', (data) => {
    const msgElement = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${data.message_id}'] .message-status`);
    if (msgElement) {
        const icon = msgElement.querySelector('i');
        msgElement.dataset.status = data.status;
        msgElement.classList.toggle('read', data.status === 'read');
        icon.className = (data.status === 'delivered' || data.status === 'read') ? 'fa-solid fa-check-double' : 'fa-solid fa-check';
    }
    // On ne recharge PLUS toute la liste ici pour éviter le saut.
    // La mise à jour se fera au prochain message. C'est un bon compromis.
});

socket.on('bulk_status_update', (data) => {
    data.message_ids.forEach(messageId => {
        const msgElement = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${messageId}'] .message-status`);
        if (msgElement) {
            const icon = msgElement.querySelector('i');
            msgElement.dataset.status = data.status;
            msgElement.classList.add('read');
            icon.className = 'fa-solid fa-check-double';
        }
    });
    // On ne recharge PLUS toute la liste ici.
});

    // Les écouteurs 'typing_status_update' et 'recording_status_update'
    // ont été retirés par le nouveau code.
    
    // Écouteurs de focus/blur clavier (Gardés de l'original)
    if (dom.messageInput) {
        const chatContainerElement = document.querySelector('.chat-container');
        dom.messageInput.addEventListener('focus', () => {
            chatContainerElement.classList.add('keyboard-visible');
            scrollToBottom();
        });

        dom.messageInput.addEventListener('blur', () => {
            chatContainerElement.classList.remove('keyboard-visible');
        });
    }

    // --- INITIALISATION ---
    loadChatrooms();
});

<< mobile_nav.js >>:  
// DANS static/js/mobile_nav.js

document.addEventListener('DOMContentLoaded', () => {
    // --- Gestion du Menu Utilisateur ---
    const userMenuButton = document.querySelector('.user-menu-button');
    const userMenuDropdown = document.querySelector('.user-menu-dropdown');

    if (userMenuButton && userMenuDropdown) {
        userMenuButton.addEventListener('click', (event) => {
            event.stopPropagation();
            userMenuDropdown.classList.toggle('active');
        });

        document.addEventListener('click', () => {
            if (userMenuDropdown.classList.contains('active')) {
                userMenuDropdown.classList.remove('active');
            }
        });
    }

    // --- NOUVEAU : Gestion de la barre de recherche ---
    const searchContainer = document.querySelector('.search-container');
    const searchIconBtn = document.getElementById('search-icon-btn');
    const searchInput = document.getElementById('search-input-header');

    if (searchIconBtn && searchContainer && searchInput) {
        searchIconBtn.addEventListener('click', (event) => {
    event.preventDefault();
    searchContainer.classList.toggle('active');
    if (searchContainer.classList.contains('active')) {
        searchInput.focus();
        // AJOUT : Animation pour éloigner
        searchIconBtn.style.transition = 'transform 0.3s ease';
        searchIconBtn.style.transform = 'translateX(-0px)'; // Ajustez la valeur pour l'espace du input
    } else {
        searchIconBtn.style.transform = 'translateX(0)';
    }
});

        // Optionnel : Ferme la recherche si on clique ailleurs
        document.addEventListener('click', (event) => {
            if (!searchContainer.contains(event.target) && searchContainer.classList.contains('active')) {
                searchContainer.classList.remove('active');
            }
        });
    }
});

<< my_posts.js >>:  
// static/js/my_posts.js (Version finale corrigée - Réintégration des boutons d'action stylisés)

document.addEventListener('DOMContentLoaded', () => {
    // --- Initialisation ---
    const container = document.getElementById('my-posts-list-container');
    const mainActionsButton = document.getElementById('main-actions-button');
    const mainActionsDropdown = document.getElementById('main-actions-dropdown');
    let allPosts = [];
    let selectedPostIds = new Set();
    let isSelectionMode = false;

    // --- FONCTIONS DE GESTION DE L'INTERFACE ---

    function enterSelectionMode() {
        if (isSelectionMode) return;
        isSelectionMode = true;
        container.classList.add('selection-mode');
        updateMainActionsMenu();
    }

    function exitSelectionMode() {
        isSelectionMode = false;
        container.classList.remove('selection-mode');
        selectedPostIds.clear();
        document.querySelectorAll('.post-card.selected').forEach(card => card.classList.remove('selected'));
        updateMainActionsMenu();
    }

    // --- GESTION DES MENUS CONTEXTUELS ---

    function updateMainActionsMenu() {
        if (!mainActionsDropdown) return;
        mainActionsDropdown.innerHTML = '';
        if (selectedPostIds.size > 0) {
            // --- MENU EN MODE SÉLECTION ---
            const selectedPosts = allPosts.filter(p => selectedPostIds.has(p.id));
            if (selectedPostIds.size === 1) {
                const post = selectedPosts[0];
                mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="${post.is_visible ? 'hide' : 'show'}-selected">${post.is_visible ? _('Hide') : _('Show')}</button>`;
                mainActionsDropdown.innerHTML += `<a href="/edit_post/${post.id}" class="dropdown-item" data-action="edit-selected">${_('Edit')}</a>`;
            } else {
                const allVisible = selectedPosts.every(p => p.is_visible);
                const allHidden = selectedPosts.every(p => !p.is_visible);
                if (allVisible) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="hide-selected">${_('Hide selection')}</button>`;
                else if (allHidden) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="show-selected">${_('Show selection')}</button>`;
            }
            mainActionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete-selected">${_('Delete selection')}</button>`;
            mainActionsDropdown.innerHTML += `<hr><button class="dropdown-item" data-action="cancel-selection">${_('Cancel selection')}</button>`;
        } else {
            // --- MENU PAR DÉFAUT ---
            if (allPosts.some(p => p.is_visible)) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="hide-all">${_('Hide all')}</button>`;
            if (allPosts.some(p => !p.is_visible)) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="show-all">${_('Show all')}</button>`;
            if (allPosts.length > 0) mainActionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete-all">${_('Delete all')}</button>`;
        }
    }

    // --- GESTION DES ACTIONS (CLICS) ---
    
     async function handleDeletePost(postId) {
        if (confirm(_('Are you sure you want to delete this ad?'))) {
            try {
                const response = await fetch(`/api/posts/${postId}`, {
                    method: 'DELETE',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } // Utilise la fonction globale
                });
                const data = await response.json();
                if (data.success) {
                    displayMessage(_('Ad deleted successfully!'), 'success');
                    allPosts = allPosts.filter(p => p.id !== postId);
                    renderMyPosts(allPosts);
                    updateMainActionsMenu();
                } else {
                    displayMessage(data.message || _('Failed to delete ad.'), 'error');
                }
            } catch (error) {
                console.error('Delete error:', error);
                displayMessage(_('An error occurred while deleting the ad.'), 'error');
            }
        }
    }

     async function handleToggleVisibility(postId) {
        const post = allPosts.find(p => p.id === postId);
        if (!post) return;
        
        const action = post.is_visible ? 'hide' : 'show';
        const confirmationMessage = post.is_visible 
            ? _('Are you sure you want to hide this ad?') 
            : _('Are you sure you want to show this ad?');

        if (confirm(confirmationMessage)) {
            try {
                // L'URL inclut maintenant "toggle_"
                const response = await fetch(`/api/posts/${postId}/toggle_visibility`, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': window.getCsrfToken() // Utilise la fonction globale
                    },
                    body: JSON.stringify({ action: action })
                });
                const data = await response.json();
                if (data.success) {
                    post.is_visible = !post.is_visible;
                    displayMessage(data.message, 'success');
                    renderMyPosts(allPosts);
                    updateMainActionsMenu();
                } else {
                    displayMessage(data.message || _('Failed to update visibility.'), 'error');
                }
            } catch (error) {
                console.error('Visibility toggle error:', error);
                displayMessage(_('An error occurred while updating the visibility.'), 'error');
            }
        }
    }

    async function performBulkAction(endpoint, body) {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify(body)
            });
            const data = await response.json();
            if (data.success) {
                displayMessage(data.message, 'success');
                await loadMyPosts();
                exitSelectionMode();
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            console.error('Bulk action error:', error);
            displayMessage(_('Failed to perform action.'), 'error');
        }
    }
    
    if (mainActionsDropdown) {
        mainActionsDropdown.addEventListener('click', async (e) => {
            const action = e.target.dataset.action;
            if (!action) return;

            let postIds;
            let confirmationMessage;
            let endpoint;
            let body;

            if (action.includes('all')) {
                postIds = allPosts.map(p => p.id);
            } else if (action.includes('selected')) {
                postIds = Array.from(selectedPostIds);
            }

            switch (action) {
                case 'hide-all':
                case 'hide-selected':
                    confirmationMessage = _("Hide all selected ads?");
                    endpoint = '/api/posts/bulk-visibility';
                    body = { post_ids: postIds, action: 'hide' };
                    break;
                case 'show-all':
                case 'show-selected':
                    confirmationMessage = _("Show all selected ads?");
                    endpoint = '/api/posts/bulk-visibility';
                    body = { post_ids: postIds, action: 'show' };
                    break;
                case 'delete-all':
                case 'delete-selected':
                    confirmationMessage = _("Permanently delete the selected ads?");
                    endpoint = '/api/posts/bulk-delete';
                    body = { post_ids: postIds };
                    break;
                case 'cancel-selection':
                    exitSelectionMode();
                    return;
                default:
                    return;
            }

            if (postIds && postIds.length > 0 && confirm(confirmationMessage)) {
                await performBulkAction(endpoint, body);
            }
        });
    }

    if (container) {
        container.addEventListener('click', (e) => {
            const card = e.target.closest('.post-card');
            if (!card) return;

            const postId = parseInt(card.dataset.postId, 10);
            
            // Si le clic vient d'un bouton d'action, on le gère et on arrête tout
            const deleteBtn = e.target.closest('.delete-button');
            const toggleBtn = e.target.closest('.toggle-visibility-button');
            
            if (deleteBtn) {
                e.preventDefault();
                handleDeletePost(postId);
                return;
            }
            if (toggleBtn) {
                e.preventDefault();
                handleToggleVisibility(postId);
                return;
            }

            // Si on est en mode sélection, on gère la sélection/désélection
            if (isSelectionMode) {
                e.preventDefault();
                if (selectedPostIds.has(postId)) {
                    selectedPostIds.delete(postId);
                    card.classList.remove('selected');
                } else {
                    selectedPostIds.add(postId);
                    card.classList.add('selected');
                }
                if (selectedPostIds.size === 0) {
                    exitSelectionMode();
                } else {
                    updateMainActionsMenu();
                }
            }
            // Si on n'est pas en mode sélection et qu'on ne clique pas sur un bouton, le lien par défaut de la carte fonctionnera.
        });

        container.addEventListener('pointerdown', (e) => {
            const card = e.target.closest('.post-card');
            if (card && !e.target.closest('.post-actions')) { // Ne pas déclencher sur les boutons
                window.pressTimer = window.setTimeout(() => {
                    if (!isSelectionMode) enterSelectionMode();
                    const postId = parseInt(card.dataset.postId, 10);
                    if (!selectedPostIds.has(postId)) {
                        selectedPostIds.add(postId);
                        card.classList.add('selected');
                        updateMainActionsMenu();
                    }
                }, 800); // 800ms pour un appui long
            }
        });
        container.addEventListener('pointerup', () => clearTimeout(window.pressTimer));
        container.addEventListener('pointerleave', () => clearTimeout(window.pressTimer));
    }

    if (mainActionsButton && mainActionsDropdown) {
        mainActionsButton.addEventListener('click', (e) => {
            e.stopPropagation();
            mainActionsDropdown.classList.toggle('show');
        });
        document.addEventListener('click', (e) => {
            if (!mainActionsButton.contains(e.target) && !mainActionsDropdown.contains(e.target)) {
                mainActionsDropdown.classList.remove('show');
            }
        });
    }

    async function loadMyPosts() {
        try {
            const response = await fetch('/api/posts/my_posts');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

            if (data.success) {
                allPosts = data.posts || [];
                renderMyPosts(allPosts);
                updateMainActionsMenu();
            } else {
                displayMessage(data.message || _('Failed to load your ads.'), 'error');
            }
        } catch (error) {
            console.error('Load my posts error:', error);
            displayMessage(_('An error occurred while loading your ads.'), 'error');
            if(container) container.innerHTML = `<p>${_('Failed to load your ads.')}</p>`;
        }
    }

    // NOUVELLE FONCTION : Rendu des posts (adapté de posts.js)
    function renderMyPosts(posts) {
        if (!container) return;
        container.innerHTML = '';
        if (posts.length === 0) {
            container.innerHTML = `<p class="empty-message">${_("You haven't posted any ads yet. Time to create your first one!")}</p>`;
            return;
        }

        posts.forEach(post => {
            const visibilityClass = post.is_visible ? '' : 'hidden-post'; // Utiliser une classe qui n'est pas "hidden" pour ne pas faire display:none
            const toggleText = post.is_visible ? _('Hide') : _('Show');
            const toggleIcon = post.is_visible ? 'fa-eye' : 'fa-eye-slash';
            
            // ### DÉBUT DE LA MODIFICATION ###
            // On enlève les boutons superposés et on crée un bloc .post-actions en bas
            const postCardHTML = `
                <div class="post-card ${visibilityClass}" data-post-id="${post.id}">
                    <a href="/posts/${post.id}" class="post-card-link">
                        ${post.cover_image_url ? `<div class="post-card-image" style="background-image: url('${post.cover_image_url}');"></div>` : ''}
                        <div class="post-card-content">
                            <span class="post-card-category category-${String(post.category).toLowerCase()}">${post.category}</span>
                            <h3>${post.title}</h3>
                            <p>${post.description.substring(0, 100)}...</p>
                        </div>
                    </a>
                    
                    <div class="post-actions">
                        <a href="/edit_post/${post.id}" class="post-action-btn edit" title="${_('Edit')}">
                            <i class="fa-solid fa-pen-to-square"></i> ${_('Edit')}
                        </a>
                        <button class="post-action-btn toggle-visibility-button" title="${toggleText}">
                            <i class="fa-solid ${toggleIcon}"></i> ${toggleText}
                        </button>
                        <button class="post-action-btn delete delete-button" title="${_('Delete')}">
                            <i class="fa-solid fa-trash"></i> ${_('Delete')}
                        </button>
                    </div>
                    </div>
            `;
            // ### FIN DE LA MODIFICATION ###

            container.insertAdjacentHTML('beforeend', postCardHTML);
        });
    }
    
    // Fonction utilitaire pour afficher des messages (si elle n'existe pas déjà)
    function displayMessage(message, type = 'info') {
        const container = document.getElementById('message-container');
        if (container) {
            const msgDiv = document.createElement('div');
            msgDiv.className = `message ${type}`;
            msgDiv.textContent = message;
            container.innerHTML = ''; // Vide les anciens messages
            container.appendChild(msgDiv);
            setTimeout(() => {
                msgDiv.style.opacity = '0';
                setTimeout(() => msgDiv.remove(), 500);
            }, 5000);
        }
    }
    
    loadMyPosts();
});

<< nav_active.js >>:  
// static/js/nav_active.js (Version corrigée et unifiée)

document.addEventListener('DOMContentLoaded', () => {
    // Normalise le chemin de l'URL pour une comparaison fiable
    // Exemple : "/posts/123/" devient "/posts"
    const currentPath = window.location.pathname;

    // Sélectionne TOUS les liens de navigation, PC et mobile
    const navItems = document.querySelectorAll('.desktop-nav-item:not(.nav-create-post), .mobile-nav-item:not(.create)');

    let isAnyLinkActive = false;

    navItems.forEach(item => {
        const itemHref = new URL(item.href).pathname;

        // Condition de correspondance simple mais efficace :
        // Si le chemin actuel COMMENCE par le chemin du lien (sauf pour la racine)
        // Ex: /posts/123 commence par /posts -> Le lien "Annonces" sera actif.
        if ( (itemHref !== '/' && currentPath.startsWith(itemHref)) || (itemHref === '/' && currentPath === '/') ) {
            item.classList.add('active');
            isAnyLinkActive = true;
        } else {
            item.classList.remove('active');
        }
    });

    // Si aucun lien ne correspond (ex: page d'accueil avec chemin vide), on active manuellement le lien "Home"
    if (!isAnyLinkActive) {
        document.querySelectorAll('a[href="/"]').forEach(homeLink => {
            if (homeLink.classList.contains('desktop-nav-item') || homeLink.classList.contains('mobile-nav-item')) {
                 homeLink.classList.add('active');
            }
        });
    }
});

<< notifications.js >>:  
// DANS static/js/notifications.js
// REMPLACEZ TOUT LE CONTENU DU FICHIER PAR CE QUI SUIT :

document.addEventListener('DOMContentLoaded', () => {
    const lang = document.documentElement.lang;
    const container = document.getElementById('notifications-list-container');
    const actionsButton = document.getElementById('main-actions-button');
    const actionsDropdown = document.getElementById('main-actions-dropdown');

    let allNotifications = [];
    let selectedNotifIds = new Set();
    let isSelectionMode = false;
    let pressTimer;

    // --- GESTION DE LA SÉLECTION ---

    function enterSelectionMode() {
        if (isSelectionMode) return;
        isSelectionMode = true;
        container.classList.add('selection-mode');
        updateActionsMenu();
    }

    function exitSelectionMode() {
        isSelectionMode = false;
        container.classList.remove('selection-mode');
        selectedNotifIds.clear();
        document.querySelectorAll('.notification-item.selected').forEach(item => {
            item.classList.remove('selected');
        });
        updateActionsMenu();
    }

    function toggleSelection(notifId, element) {
        if (selectedNotifIds.has(notifId)) {
            selectedNotifIds.delete(notifId);
            element.classList.remove('selected');
        } else {
            selectedNotifIds.add(notifId);
            element.classList.add('selected');
        }

        if (selectedNotifIds.size === 0) {
            exitSelectionMode();
        } else {
            updateActionsMenu();
        }
    }

    // --- MISE À JOUR DU MENU D'ACTIONS ---

    function updateActionsMenu() {
        actionsDropdown.innerHTML = '';
        if (isSelectionMode && selectedNotifIds.size > 0) {
            // Menu contextuel (quand des items sont sélectionnés)
            const count = selectedNotifIds.size;
            const markAsReadText = count > 1 ? `Mark the ${count} as read` : 'Mark as read';
            const deleteText = count > 1 ? `Delete the ${count}` : 'Delete';

            actionsDropdown.innerHTML += `<button class="dropdown-item" data-action="mark_read_selected">${markAsReadText}</button>`;
            actionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete_selected">${deleteText}</button>`;
            actionsDropdown.innerHTML += `<hr><button class="dropdown-item" data-action="cancel_selection">Cancel selection</button>`;
        } else {
            // Menu par défaut
            if (allNotifications.length > 0) {
                actionsDropdown.innerHTML += `<button class="dropdown-item" data-action="mark_read_all">Mark all as read</button>`;
                actionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete_all">Delete all</button>`;
            } else {
                 actionsDropdown.innerHTML = `<span class="dropdown-item" style="color: grey;">No action</span>`;
            }
        }
    }

    // --- GESTION DES ÉVÉNEMENTS ---

    async function handleAction(action) {
        let confirmationMessage, apiAction, idsToSend = [];
        
        switch (action) {
            case 'mark_read_all':
                apiAction = 'mark_read';
                break;
            case 'delete_all':
                confirmationMessage = _('Do you really want to delete ALL your notifications?');
                apiAction = 'delete';
                break;
            case 'mark_read_selected':
                apiAction = 'mark_read';
                idsToSend = Array.from(selectedNotifIds);
                break;
            case 'delete_selected':
                confirmationMessage = `Do you really want to delete the ${selectedNotifIds.size} selected notifications?`;
                apiAction = 'delete';
                idsToSend = Array.from(selectedNotifIds);
                break;
            case 'cancel_selection':
                exitSelectionMode();
                return;
        }

        if (confirmationMessage && !confirm(confirmationMessage)) {
            return;
        }

        try {
            const response = await fetch('/api/notifications/bulk-actions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify({ action: apiAction, notif_ids: idsToSend })
            });
            const data = await response.json();
            displayMessage(data.message, response.ok ? 'success' : 'error');
            if (response.ok) {
                exitSelectionMode();
                loadNotifications(); // Recharger la liste
            }
        } catch (error) {
            displayMessage(lang === 'fr' ? 'Erreur réseau.' : 'Network error.', 'error');
        }
    }

    // --- RENDU ET CHARGEMENT ---

    async function loadNotifications() {
        try {
            const response = await fetch('/api/notifications');
            const data = await response.json();
            if (data.success) {
                allNotifications = data.notifications;
                renderNotifications(allNotifications);
                actionsButton.style.display = allNotifications.length > 0 ? 'block' : 'none';
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(lang === 'fr' ? 'Erreur réseau.' : 'Network error.', 'error');
        }
    }

    function renderNotifications(notifs) {
        container.innerHTML = '';
        if (notifs.length === 0) {
            container.innerHTML = `<p>${lang === 'fr' ? 'Aucune notification.' : 'No notification.'}</p>`;
            return;
        }
        notifs.forEach(notif => {
            const item = document.createElement('div');
            item.className = 'notification-item' + (notif.is_read ? ' read' : '');
            item.dataset.notifId = notif.id;

            const actorInitial = notif.actor_username ? notif.actor_username.charAt(0).toUpperCase() : '?';
            const iconClass = notif.type === 'favorite' ? 'fa-bookmark' : 'fa-star';

            item.innerHTML = `
                <div class="selection-overlay"></div>
                <div class="notif-avatar">${actorInitial}</div>
                <div class="notif-content">
                    <p><strong>${notif.actor_username || '[User]'}</strong> ${notif.message}</p>
                    <span class="timestamp">${new Date(notif.timestamp).toLocaleString(lang)}</span>
                    <i class="notif-icon fas ${iconClass}"></i>
                </div>
            `;
            container.appendChild(item);
        });
    }

    // --- ÉCOUTEURS D'ÉVÉNEMENTS PRINCIPAUX ---
    
    // Clic sur le bouton de menu
    actionsButton.addEventListener('click', (e) => {
        e.stopPropagation();
        updateActionsMenu();
        actionsDropdown.classList.toggle('show');
    });

    // Clic sur une action dans le menu
    actionsDropdown.addEventListener('click', (e) => {
        const action = e.target.dataset.action;
        if (action) {
            handleAction(action);
            actionsDropdown.classList.remove('show');
        }
    });
    
    // Clics sur la liste des notifications (sélection ou navigation)
    container.addEventListener('click', async (e) => {
        const item = e.target.closest('.notification-item');
        if (!item) return;
        
        const notifId = parseInt(item.dataset.notifId, 10);
        const notification = allNotifications.find(n => n.id === notifId);

        if (isSelectionMode || e.ctrlKey) {
            e.preventDefault();
            enterSelectionMode();
            toggleSelection(notifId, item);
        } else {
            // Comportement normal : marquer comme lu et naviguer
            if (notification && notification.link) {
                window.location.href = notification.link;
            }
            if (!notification.is_read) {
                await fetch(`/api/notifications/${notifId}/read`, { method: 'POST', headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } });
            }
        }
    });

    // Gestion du clic long pour mobile
    container.addEventListener('pointerdown', (e) => {
        const item = e.target.closest('.notification-item');
        if (item) {
            pressTimer = window.setTimeout(() => {
                enterSelectionMode();
                toggleSelection(parseInt(item.dataset.notifId, 10), item);
            }, 800); // 800ms pour un appui long
        }
    });

    container.addEventListener('pointerup', () => {
        clearTimeout(pressTimer);
    });

    // Fermer le menu si on clique n'importe où ailleurs
    document.addEventListener('click', () => {
        if (actionsDropdown.classList.contains('show')) {
            actionsDropdown.classList.remove('show');
        }
    });

    // Chargement initial
    loadNotifications();
});

<< post_detail.js >>:  
// static/js/post_detail.js (Version complète et corrigée)

document.addEventListener('DOMContentLoaded', () => {
    const container = document.querySelector('.post-detail-container');
    const currentUserId = localStorage.getItem('user_id');

    async function toggleFavorite(postId, buttonElement) {
        const csrfToken = window.getCsrfToken();
        if (!csrfToken) {
            window.location.href = '/login';
            return;
        }
        try {
            const response = await fetch(`/api/posts/${postId}/favorite`, {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': csrfToken }
            });
            const data = await response.json();
            if (data.success) {
                buttonElement.classList.toggle('favorited', data.status === 'added');
            }
        } catch (error) {
            console.error(_('Error adding/removing favorite:'), error);
        }
    }

    async function fetchPostDetails() {
        displayMessage(_('Loading...'), 'info');
        try {
            const response = await fetch(`/api/posts/${POST_ID}`);
            const data = await response.json();
            document.getElementById('message-container').innerHTML = '';
            
            if (data.success) {
                renderPost(data.post);
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            console.error(error);
            displayMessage(_('Network error.'), 'error');
        }
    }

    // dans static/js/post_detail.js
// Remplacez votre fonction renderPost existante par celle-ci :

// DANS static/js/post_detail.js
// REMPLACEZ toute l'ancienne fonction renderPost par celle-ci :

// DANS static/js/post_detail.js
// REMPLACEZ toute l'ancienne fonction renderPost par celle-ci :

function renderPost(post) {
    const favoritedClass = post.is_favorited ? 'favorited' : '';

    let imagesHTML = '';
    const imageCount = post.image_urls ? post.image_urls.length : 0;

    if (imageCount > 0) {
        // Le conteneur principal a maintenant un ID "lightgallery"
        // Chaque image est maintenant un lien <a> qui pointe vers l'image en haute résolution
        imagesHTML = `
            <div id="lightgallery" class="photo-grid" data-count="${imageCount}">
                ${post.image_urls.map(url => `
                    <a href="${url}">
                        <img src="${url}" alt="Ad image">
                    </a>
                `).join('')}
            </div>
        `;
    }

    const locationsDetailHTML = post.locations && post.locations.length > 0 ? `
        <div class="post-detail-location">
            <i class="fa-solid fa-map-marker-alt"></i>
            <strong>${post.locations.join(' / ')}</strong>
        </div>
    ` : '';

    container.innerHTML = `
        <div class="post-detail-image-container">
            ${imagesHTML}
            <button class="favorite-btn ${favoritedClass}" data-post-id="${post.id}" title="Save">
                <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
            </button>
        </div>
        <div class="post-detail-content">
            <div class="post-detail-header"><h1>${post.title}</h1><span class="post-card-category">${post.category}</span></div>
            <div class="post-detail-meta">
                <span>Published by <strong><a href="/profile/${post.author_username}?from_post=${post.id}">${post.author_username}</a></strong> on ${new Date(post.timestamp).toLocaleDateString()}</span>
                ${locationsDetailHTML} </div>
            <p class="post-detail-description">${post.description.replace(/\n/g, '<br>')}</p>
            <div id="contact-section"></div>
        </div>
    `;
    
    // --- NOUVELLE LIGNE MAGIQUE ---
    // On active la LightGallery sur notre conteneur d'images
    const gallery = document.getElementById('lightgallery');
    if (gallery) {
        lightGallery(gallery);
    }

    renderContactButton(post.user_id);
    
    const favoriteBtn = container.querySelector('.favorite-btn');
    if (favoriteBtn) {
        favoriteBtn.addEventListener('click', () => {
             toggleFavorite(post.id, favoriteBtn);
        });
    }
}
    function renderContactButton(authorId) {
        const contactSection = document.getElementById('contact-section');
        if (!currentUserId) {
            contactSection.innerHTML = `<p>You must be <a href="/login">logged in</a> to contact the author.</p>`;
        } else if (currentUserId === String(authorId)) {
            contactSection.innerHTML = `<p>This is your ad. You can <a href="/edit_post/${POST_ID}">edit it here</a>.</p>`;
        } else {
            const button = document.createElement('button');
            button.id = 'chat-button';
            button.className = 'button-primary';
            button.textContent = _('Contact via Message');
            button.dataset.authorId = authorId;
            contactSection.appendChild(button);
            button.addEventListener('click', startChat);
        }
    }

    // DANS static/js/post_detail.js, REMPLACEZ la fonction startChat

async function startChat(event) {
    const participantId = event.target.dataset.authorId;
    displayMessage(_('Starting chat...'), 'info');
    try {
        const response = await fetch('/api/chat/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': window.getCsrfToken()
            },
            // On envoie maintenant l'ID de l'annonce en plus de l'ID de l'auteur
            body: JSON.stringify({ 
                participant_id: participantId,
                post_id: POST_ID // POST_ID est déjà défini dans ce fichier
            })
        });
        const data = await response.json();
        if (data.success) {
            window.location.href = `/messages?chatroom_id=${data.chatroom_id}`;
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        displayMessage(error.message || _("Error creating chat."), 'error');
    }
}
    fetchPostDetails();
});

<< posts.js >>:  
// static/js/posts.js (Version finale avec async DOMContentLoaded et Choices pour filtre)

document.addEventListener('DOMContentLoaded', async () => {  // ← RENDU ASYNC
    const container = document.getElementById('posts-list-container');
    const searchInput = document.getElementById('search-input');
    const categoryNav = document.querySelector('.category-nav');
    const typeFilter = document.getElementById('type-filter');
    const sortFilter = document.getElementById('sort-filter');
    const locationFilter = document.getElementById('location-filter');  // Pour Choices
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('focus_search') === 'true' && searchInput) {
        searchInput.focus();
        // Optionnel : on nettoie l'URL pour ne pas garder le paramètre
        history.replaceState(null, '', window.location.pathname); 
    }

    // --- VARIABLES D'ÉTAT ---

    let currentType = '';
    let currentSort = 'newest';
    let currentCategory = '';
    let currentSearchTerm = '';
    let currentLocations = [];
    
    let page = 1;
    let hasMore = true;
    let isLoading = false;
    let searchTimeout;
    
    // Init Choices pour filtre location (multiple=true pour multi-sélection)
    let locationChoicesInstance = null;
    if (locationFilter) {
        try {
            locationChoicesInstance = await initAdvancedLocationSelector('location-filter', true);
            if (locationChoicesInstance) {
                locationChoicesInstance.passedElement.element.addEventListener('change', () => {
                    currentLocations = locationChoicesInstance.getValue(true).map(item => 
                        typeof item === 'object' ? item.value : item
                    );
                    loadInitialPosts();
                });
            }
        } catch (err) {
            console.error('Failed to init location filter:', err);
        }
    }

    // --- FONCTIONS PRINCIPALES ---

    async function loadInitialPosts() {
        page = 1;
        hasMore = true;
        container.innerHTML = '';
        displayMessage(_('Loading...'), 'info');
        await fetchAndRenderPosts();
        document.getElementById('message-container').innerHTML = '';
    }

    async function fetchAndRenderPosts() {
        if (!hasMore || isLoading) return;
        isLoading = true;
        
        const url = new URL('/api/posts', window.location.origin);
        url.searchParams.append('page', page);
        if (currentCategory) url.searchParams.append('category', currentCategory);
        if (currentSearchTerm) url.searchParams.append('search', currentSearchTerm);
        if (currentType) url.searchParams.append('type', currentType);
        if (currentSort) url.searchParams.append('sort', currentSort);
        // Mapper currentLocations vers params (strings)
        currentLocations.forEach(loc => url.searchParams.append('locations', loc));

        try {
            const response = await fetch(url);
            const data = await response.json();

            if (data.success) {
                renderPosts(data.posts);
                hasMore = data.has_next;
                page++;
                if (!hasMore && container.innerHTML === '') {
                     container.innerHTML = `<p>${_("No ad matches your search.")}</p>`;
                }
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(_('Network error.'), 'error');
        } finally {
            isLoading = false;
        }
    }

    function renderPosts(posts) {
        // Si la page est la première et qu'il n'y a aucun post, on affiche un message.
        if (posts.length === 0 && page === 1) {
            const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
            if(container) container.innerHTML = '<p>' + _("No ad found.") + '</p>';
            return;
        }

        posts.forEach(post => {
            const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
            if (!container) return;
            
            const favoritedClass = post.is_favorited ? 'favorited' : '';
            let authorAvatarHTML = post.author_photo_url ?
                `<a href="#" class="author-avatar-link" data-img-url="${post.author_photo_url}" title="${_('View photo')}"><img src="${post.author_photo_url}" class="author-avatar" alt="Author"></a>` :
                `<div class="author-avatar default-avatar">${post.author_username[0].toUpperCase()}</div>`;
            
            const locationsHTML = post.locations && post.locations.length > 0 ?
                `<div class="post-card-location"><i class="fa-solid fa-map-marker-alt"></i><span>${post.locations.join(', ')}</span></div>` : '';
            
            const profileLink = `/profile/${post.author_username}`;
            
            const postCardHTML = `
                <div class="post-card">
                    <button class="favorite-btn ${favoritedClass}" data-post-id="${post.id}" title="${_('Save')}">
                        <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
                    </button>
                    <a href="/posts/${post.id}" class="post-card-link">
                        ${post.cover_image_url ? `<div class="post-card-image" style="background-image: url('${post.cover_image_url}');"></div>` : ''}
                        <div class="post-card-content">
                            <span class="post-card-category category-${post.category.toLowerCase()}">${post.category}</span>
                            <h3>${post.title}</h3>
                            ${locationsHTML}
                        </div>
                    </a>
                    <div class="post-card-footer-new">
                        <div class="footer-left">
                            ${authorAvatarHTML}
                            <a href="${profileLink}" title="${_('View profile')}">${post.author_username}</a>
                        </div>
                        <div class="footer-center interactive-footer-item" 
     data-message="${_('%(count)s people interact with this ad.', {count: post.interest_count})}" 
     data-author-id="${post.user_id}" 
     data-post-id="${post.id}" 
     title="${_('View interactions')}">
                            <i class="fa-solid fa-comments"></i>
                            <span>${post.interest_count}</span>
                        </div>
                        <div class="footer-right interactive-footer-item" data-message="${_('This ad has been viewed %(count)s times.', {count: post.view_count})}" title="${_('View views')}">
                            <i class="fa-solid fa-eye"></i>
                            <span>${post.view_count}</span>
                        </div>
                    </div>
                </div>
            `;
            container.insertAdjacentHTML('beforeend', postCardHTML);
        });
    }

    async function toggleFavorite(postId, buttonElement) {
        const csrfToken = window.getCsrfToken();
        if (!csrfToken) {
            window.location.href = '/login';
            return;
        }
        try {
            const response = await fetch(`/api/posts/${postId}/favorite`, {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': csrfToken }
            });
            const data = await response.json();
            if (data.success) {
                buttonElement.classList.toggle('favorited', data.status === 'added');
            }
        } catch (error) {
            console.error(_("Error adding/removing favorite:"), error);
        }
    }

    // --- ÉCOUTEURS D'ÉVÉNEMENTS ---

    // Scroll infini
    window.addEventListener('scroll', () => {
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 200) {
            fetchAndRenderPosts();
        }
    });

    // Recherche
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                currentSearchTerm = searchInput.value;
                loadInitialPosts();
            }, 500);
        });
    }

    // Filtres
    if (typeFilter) {
        typeFilter.addEventListener('change', () => {
            currentType = typeFilter.value;
            loadInitialPosts();
        });
    }
    if (sortFilter) {
        sortFilter.addEventListener('change', () => {
            currentSort = sortFilter.value;
            loadInitialPosts();
        });
    }

    // *** CORRECTION POUR LES CATÉGORIES ACTIVES ***
    if (categoryNav) {
        categoryNav.addEventListener('click', (e) => {
            const clickedButton = e.target.closest('.category-nav-item');
            if (!clickedButton) return;

            // 1. Retirer la classe 'active' de tous les boutons
            categoryNav.querySelectorAll('.category-nav-item').forEach(btn => {
                btn.classList.remove('active');
            });

            // 2. Ajouter la classe 'active' au bouton cliqué
            clickedButton.classList.add('active');

            // 3. Mettre à jour la catégorie et recharger les annonces
            currentCategory = clickedButton.dataset.category;
            loadInitialPosts();
        });
    }

    // Clic sur les boutons favoris (délégation d'événement)
    container.addEventListener('click', (event) => {
        const favoriteBtn = event.target.closest('.favorite-btn');
        if (favoriteBtn) {
            event.preventDefault(); 
            const postId = favoriteBtn.dataset.postId;
            toggleFavorite(postId, favoriteBtn);
        }
    });

    // --- SUPPRIMÉ populateFilters natif : Utilise Choices pour cohérence (déjà géré dans init)

    // Chargement initial
    loadInitialPosts();
});

<< profile.js >>:  
// static/js/profile.js (Version mise à jour)

document.addEventListener('DOMContentLoaded', () => {

    const chatButton = document.getElementById('chat-button');
    const currentUserId = localStorage.getItem('user_id');

    if (chatButton) {
        // Logique pour masquer le bouton si c'est notre propre profil
        if (!currentUserId || chatButton.dataset.authorId === currentUserId) {
            chatButton.style.display = 'none';
        }

        // Écouteur de clic mis à jour
        chatButton.addEventListener('click', async (event) => {
            const button = event.target;
            const participantId = button.dataset.authorId;
            
            // *** NOUVELLE LIGNE ***
            // On récupère l'ID du post depuis l'attribut data-post-id (il peut être absent)
            const postId = button.dataset.postId; 

            displayMessage(_('Starting conversation...'), 'info');

            try {
                // On prépare le corps de la requête
                const requestBody = {
                    participant_id: participantId
                };

                // Si on a un postId, on l'ajoute au corps de la requête
                if (postId) {
                    requestBody.post_id = postId;
                }

                const response = await fetch('/api/chat/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': window.getCsrfToken()
                    },
                    body: JSON.stringify(requestBody)
                });

                const data = await response.json();
                if (data.success) {
                    window.location.href = `/messages?chatroom_id=${data.chatroom_id}`;
                } else {
                    throw new Error(data.message);
                }
            } catch (error) {
                displayMessage(error.message || _("Error creating conversation."), 'error');
            }
        });
    }

    // --- GESTION DE LA MODALE PHOTO (ne change pas) ---
    const photoModal = document.getElementById('photo-modal');
    const modalImage = document.getElementById('modal-image');
    const clickablePhoto = document.querySelector('.profile-photo-clickable');
    
    if (photoModal && modalImage && clickablePhoto) {
        clickablePhoto.addEventListener('click', () => {
            modalImage.src = clickablePhoto.src;
            photoModal.classList.remove('hidden');
        });
        const closeBtn = photoModal.querySelector('.close-modal-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => photoModal.classList.add('hidden'));
        }
        photoModal.addEventListener('click', (e) => {
            if (e.target === photoModal) photoModal.classList.add('hidden');
        });
    }
});

<< push-notifications.js >>:  
// static/js/push-notifications.js

// Fonction pour convertir la clé publique VAPID
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function subscribeUser() {
  if ('serviceWorker' in navigator && 'PushManager' in window) {
    try {
      const registration = await navigator.serviceWorker.ready;

      // Vérifie permission (essentiel pour mobile)
      let permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        console.log(_('Permission denied.'));
        return;
      }

      let subscription = await registration.pushManager.getSubscription();

      if (subscription === null) {
        subscription = await registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
        });
      }

      await fetch('/api/save-subscription', {
        method: 'POST',
        body: JSON.stringify(subscription),
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': window.getCsrfToken()
        }
      });
      console.log(_('Push subscription saved.'));

    } catch (error) {
      console.error(_('Push subscription failed: '), error);
    }
  }
}

// Appelle subscribeUser() au load ou sur bouton si besoin
// Lance le processus d'abonnement
subscribeUser();

<< pwa_install.js >>:  
let deferredPrompt;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  // Affiche un bouton install si désiré
  const installBtn = document.getElementById('install-btn');  // Ajoute <button id="install-btn">Installer App</button> dans base.html si besoin
  if (installBtn) installBtn.style.display = 'block';
});

if (installBtn) {
  installBtn.addEventListener('click', async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      console.log(`User response to install: ${outcome}`);
      deferredPrompt = null;
    }
  });
}

<< register.js >>:  
// Fichier : register.js (version corrigée)

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    let locationChoicesInstance = null; 

    // NOUVEAU : Référence au bouton de soumission
    const submitButton = registerForm.querySelector('button[type="submit"]');

    // Initialisation du sélecteur de localisation
    const locationSelect = document.getElementById('location-selector');
    if (locationSelect) {
        window.initAdvancedLocationSelector('location-selector').then(instance => {
            locationChoicesInstance = instance;
            console.log('Location instance initialized:', instance);
        }).catch(err => {
            console.error('Failed to init location selector:', err);
        });
    }

    // --- LOGIQUE DE VALIDATION DU MOT DE PASSE (inchangée) ---
    const rules = {
        length: document.getElementById('length-rule'),
        lower: document.getElementById('lower-rule'),
        upper: document.getElementById('upper-rule'),
        number: document.getElementById('number-rule')
    };
    let passwordIsValid = { length: false, lower: false, upper: false, number: false };

    if (passwordInput) {
        passwordInput.addEventListener('input', () => {
            const pass = passwordInput.value;
            passwordIsValid.length = pass.length >= 6;
            passwordIsValid.lower = /[a-z]/.test(pass);
            passwordIsValid.upper = /[A-Z]/.test(pass);
            passwordIsValid.number = /[0-9]/.test(pass);
            for (const rule in rules) {
                const el = rules[rule];
                if(el) {
                    el.classList.toggle('valid', passwordIsValid[rule]);
                    el.classList.toggle('invalid', !passwordIsValid[rule]);
                }
            }
        });
    }

    // --- LOGIQUE DE SOUMISSION DU FORMULAIRE (corrigée) ---
    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            // --- DÉBUT DE LA CORRECTION ---
            // On désactive le bouton immédiatement pour éviter les double-clics
            submitButton.disabled = true;
            submitButton.textContent = _('Inscription en cours...'); // Optionnel : informer l'utilisateur
            // --- FIN DE LA CORRECTION ---

            const allValid = Object.values(passwordIsValid).every(val => val === true);
            if (!allValid) {
                displayMessage(_('The password does not meet all the rules.'), 'error');
                // On réactive le bouton en cas d'erreur
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
                return;
            }

            const password = registerForm.password.value;
            const confirmPassword = registerForm.confirm_password.value;
            if (password !== confirmPassword) {
                displayMessage(_('The passwords do not match.'), 'error');
                // On réactive le bouton en cas d'erreur
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
                return;
            }

            let locationValue = '';
            if (locationChoicesInstance && typeof locationChoicesInstance.getValue === 'function') {
                const val = locationChoicesInstance.getValue();
                if (Array.isArray(val) && val.length > 0) {
                    locationValue = val[0].value || ''; 
                } else if (val && typeof val === 'object' && val.value) {
                    locationValue = val.value; 
                } else {
                    locationValue = val || ''; 
                }
            } else {
                locationValue = locationSelect ? locationSelect.value : '';
            }
            console.log('Sending location:', locationValue); 

            if (!locationValue) {
                displayMessage(_('Please select your department.'), 'error');
                // On réactive le bouton en cas d'erreur
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
                return;
            }

            const registrationData = {
                username: registerForm.username.value,
                email: registerForm.email.value,
                password: password,
                location: locationValue
            };

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(registrationData)
                });
                const data = await response.json();

                if (data.success) {
                    displayMessage(data.message, 'success');
                    registerForm.reset();
                    if(locationChoicesInstance) locationChoicesInstance.destroy();
                    // En cas de succès, on laisse tout désactivé
                    registerForm.querySelectorAll('input, select').forEach(el => el.disabled = true);
                    document.querySelector('.form-footer-text').innerHTML = _('Please check your email to activate your account.');
                } else {
                    displayMessage(data.message, 'error');
                    // S'il y a une erreur du serveur, on réactive le bouton
                    submitButton.disabled = false;
                    submitButton.textContent = _('Sign up');
                }
            } catch (error) {
                console.error(_("Registration error:"), error);
                displayMessage(_('A network error occurred.'), 'error');
                // En cas d'erreur réseau, on réactive aussi le bouton
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
            }
        });
    }
});

<< reset_password.js >>:  
// static/js/reset_password.js

document.addEventListener('DOMContentLoaded', () => {
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    const passwordInput = document.getElementById('password');
    
    // Logique de validation des règles du mot de passe (similaire à register.js)
    const rules = {
        length: document.getElementById('length-rule'),
        lower: document.getElementById('lower-rule'),
        upper: document.getElementById('upper-rule'),
        number: document.getElementById('number-rule')
    };
    let passwordIsValid = { length: false, lower: false, upper: false, number: false };

    if (passwordInput) {
        passwordInput.addEventListener('input', () => {
            const pass = passwordInput.value;
            passwordIsValid.length = pass.length >= 6;
            passwordIsValid.lower = /[a-z]/.test(pass);
            passwordIsValid.upper = /[A-Z]/.test(pass);
            passwordIsValid.number = /[0-9]/.test(pass);
            for (const rule in rules) {
                if (passwordIsValid[rule]) {
                    rules[rule].classList.remove('invalid');
                    rules[rule].classList.add('valid');
                } else {
                    rules[rule].classList.remove('valid');
                    rules[rule].classList.add('invalid');
                }
            }
        });
    }
    
    // Logique de soumission du formulaire
    if (resetPasswordForm) {
        resetPasswordForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            const allValid = Object.values(passwordIsValid).every(val => val === true);
            if (!allValid) {
                displayMessage(_('The password does not meet all the rules.'), 'error');
                return;
            }

            const password = resetPasswordForm.password.value;
            const confirmPassword = resetPasswordForm.confirm_password.value;
            const token = resetPasswordForm.token.value;

            if (password !== confirmPassword) {
                displayMessage(_('The passwords do not match.'), 'error');
                return;
            }

            try {
                const response = await fetch('/api/reset_password_with_token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: token, password: password })
                });
                const data = await response.json();

                if (data.success) {
                    displayMessage(_('Password reset successfully! Redirecting...'), 'success');
                    setTimeout(() => {
                        window.location.href = '/login?message=password_reset_success';
                    }, 2000);
                } else {
                    displayMessage(data.message, 'error');
                }
            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error');
            }
        });
    }
});

<< scroll-animation.js >>:  
// static/js/scroll-animation.js

document.addEventListener('DOMContentLoaded', () => {
    // Sélectionne tous les éléments que l'on veut animer
    const elementsToAnimate = document.querySelectorAll('.post-card, .form-step, .help-section');

    // L'Intersection Observer est une API moderne et efficace pour détecter la visibilité
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // Si l'élément entre dans le champ de vision
            if (entry.isIntersecting) {
                // On lui ajoute la classe 'visible' qui déclenchera l'animation CSS
                entry.target.classList.add('visible');
                // On arrête de l'observer pour ne pas répéter l'animation
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1 // L'animation se déclenche quand 10% de l'élément est visible
    });

    // On demande à l'observateur de surveiller chaque élément
    elementsToAnimate.forEach(element => {
        observer.observe(element);
    });
});

<< service-worker.js >>:  
// Version 6: Incrémentez ce numéro pour forcer la mise à jour du cache
const CACHE_NAME = 'business-pwa-cache-v33'; 
const urlsToCache = [
  '/',
  '/login',
  '/posts',
  '/static/css/style.css',
  '/static/js/auth_check.js',
  '/static/images/favicon-192x192.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css'
];

// 1. Installation: Mise en cache des ressources essentielles
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache ouvert');
        return cache.addAll(urlsToCache);
      })
  );
  self.skipWaiting(); // Force le nouveau Service Worker à s'activer immédiatement
});

// 2. Activation: Nettoyage des anciens caches
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            console.log('Suppression de l\'ancien cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  return self.clients.claim(); // Prend le contrôle de toutes les pages ouvertes
});

// 3. Fetch: Interception des requêtes réseau (AVEC LA CORRECTION FINALE)
self.addEventListener('fetch', event => {
    const { request } = event;

    // Pour les requêtes API ou non-GET, on va toujours sur le réseau, sans mise en cache.
    if (request.url.includes('/api/') || request.method !== 'GET') {
        event.respondWith(fetch(request));
        return;
    }

    // Stratégie "Réseau d'abord, puis cache" pour les fichiers CSS et JS
    if (request.url.endsWith('.css') || request.url.endsWith('.js')) {
        event.respondWith(
            fetch(request)
                .then(networkResponse => {
                    const responseClone = networkResponse.clone();
                    // *** CORRECTION : On ne met en cache que les réponses complètes (status 200) ***
                    if (networkResponse.status === 200) {
                        caches.open(CACHE_NAME).then(cache => {
                            cache.put(request, responseClone);
                        });
                    }
                    return networkResponse;
                })
                .catch(() => {
                    // Si le réseau échoue, on cherche dans le cache
                    return caches.match(request);
                })
        );
        return;
    }

    // Stratégie "Cache d'abord, puis réseau" pour tout le reste (pages, polices, images...)
    event.respondWith(
        caches.match(request).then(cachedResponse => {
            if (cachedResponse) {
                return cachedResponse; // Servir depuis le cache
            }
            // Sinon, aller chercher sur le réseau et mettre en cache
            return fetch(request).then(networkResponse => {
                const responseClone = networkResponse.clone();
                // *** CORRECTION : On applique la même vérification ici ***
                if (networkResponse.status === 200) {
                    caches.open(CACHE_NAME).then(cache => {
                        cache.put(request, responseClone);
                    });
                }
                return networkResponse;
            });
        })
    );
});


// 4. Push: Réception d'une notification push
self.addEventListener('push', event => {
    const data = event.data.json();
    const title = data.title || "Nouvelle Notification";
    const options = {
        body: data.body,
        icon: data.icon || '/static/images/favicon-192x192.png',
        badge: data.badge || '/static/images/logo-badge-b.png',
        data: {
            url: data.data.url 
        }
    };
    event.waitUntil(self.registration.showNotification(title, options));
});

// 5. Notification Click: Gestion du clic sur une notification
self.addEventListener('notificationclick', event => {
    event.notification.close();
    const urlToOpen = new URL(event.notification.data.url, self.location.origin).href;

    const promiseChain = clients.matchAll({
        type: 'window',
        includeUncontrolled: true
    }).then(clientList => {
        for (const client of clientList) {
            if (client.url === urlToOpen && 'focus' in client) {
                return client.focus();
            }
        }
        if (clients.openWindow) {
            return clients.openWindow(urlToOpen);
        }
    });

    event.waitUntil(promiseChain);
});

<< set_profile_photo.js >>:  
document.addEventListener('DOMContentLoaded', () => {
    const uploadArea = document.getElementById('upload-area');
    const photoInput = document.getElementById('photo-input');
    const previewContainer = document.getElementById('preview-container');
    const previewImg = document.getElementById('preview-img');
    const uploadBtn = document.getElementById('upload-btn');
    const ignoreBtn = document.getElementById('ignore-btn');
    const cancelBtn = document.getElementById('cancel-btn');

    // Drag & drop
    uploadArea.addEventListener('dragover', (e) => e.preventDefault());
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) handleFile(file);
    });
    uploadArea.addEventListener('click', () => photoInput.click());
    photoInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleFile(file);
    });

    function handleFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewContainer.classList.remove('hidden');
        };
        reader.readAsDataURL(file);
    }

    uploadBtn.addEventListener('click', async () => {
        const formData = new FormData();
        formData.append('file', photoInput.files[0]);
        try {
            const response = await fetch('/api/user/profile-photo', {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: formData
            });
            const data = await response.json();
            if (data.success) {
                displayMessage(_('Photo saved!'), 'success');
                setTimeout(() => window.location.href = '/', 1500);
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(_('Upload error'), 'error');
        }
    });

    ignoreBtn.addEventListener('click', () => window.location.href = '/');
    cancelBtn.addEventListener('click', () => {
        previewContainer.classList.add('hidden');
        photoInput.value = '';
    });
});

<< settings.js >>:  
// Dans static/js/settings.js (Version finale et unifiée)

document.addEventListener('DOMContentLoaded', () => {

    // --- Fonctions génériques pour gérer les modales ---
    const openModal = (modal) => modal.classList.remove('hidden');
    const closeModal = (modal) => modal.classList.add('hidden');

    // --- GESTION DES MODALES ---
    const profileModal = document.getElementById('profile-modal');
    const passwordModal = document.getElementById('password-modal');
    const deleteModal = document.getElementById('delete-confirm-modal');

    // Boutons d'ouverture
    const openProfileBtn = document.getElementById('open-profile-modal');
    if (openProfileBtn) openProfileBtn.addEventListener('click', () => openModal(profileModal));

    const openPasswordBtn = document.getElementById('open-password-modal');
    if (openPasswordBtn) openPasswordBtn.addEventListener('click', () => openModal(passwordModal));

    const openDeleteBtn = document.getElementById('open-delete-modal');
    if (openDeleteBtn) openDeleteBtn.addEventListener('click', () => {
        if (confirm(_("Attention: This action is irreversible. Do you really want to continue?"))) {
            openModal(deleteModal);
        }
    });

    // Boutons de fermeture
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        const closeBtn = modal.querySelector('.close-modal-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => closeModal(modal));
        }
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal(modal);
        });
    });
    const cancelDeleteBtn = document.querySelector('.cancel-delete-btn');
    if (cancelDeleteBtn) cancelDeleteBtn.addEventListener('click', () => closeModal(deleteModal));


    // --- GESTION DU CHANGEMENT DE LANGUE ---
    const languageSwitcher = document.querySelector('#language-switcher');
    if (languageSwitcher) {
        languageSwitcher.addEventListener('change', async (e) => {
            const lang = e.target.value;
            try {
                const response = await fetch('/api/user/change_language', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ language: lang })
                });
                const data = await response.json();
                if (response.ok) {
                    location.reload(true);
                } else {
                    displayMessage(data.message, 'error', 'settings-message-container');
                }
            } catch (error) {
                displayMessage(_('Network error.'), 'error', 'settings-message-container');
            }
        });
    }

    // --- GESTION DU FORMULAIRE DE PROFIL ---
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;

            try {
                const response = await fetch('/api/user/profile', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ username, email })
                });
                const data = await response.json();
                displayMessage(data.message, response.ok ? 'success' : 'error', 'settings-message-container');
                if (response.ok) closeModal(profileModal);
            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error', 'settings-message-container');
            }
        });
    }

    // --- GESTION DE LA PHOTO DE PROFIL ---
    const photoUploadContainer = document.getElementById('photo-upload-container');
    if (photoUploadContainer) {
        const photoFile = document.getElementById('photo-file');
        const previewWrapper = document.getElementById('photo-preview-wrapper');
        const buttonsWrapper = document.getElementById('photo-buttons-wrapper');
        const usernameInput = document.getElementById('username');

        const handleUpload = async (file) => {
            const formData = new FormData();
            formData.append('file', file);
            try {
                const response = await fetch('/api/user/profile-photo', {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() }
                });
                const data = await response.json();
                if (response.ok && data.photo_url) {
                    previewWrapper.innerHTML = `<img id="current-photo" src="${data.photo_url}?t=${new Date().getTime()}" alt="Profile photo" class="current-photo-preview">`;
                    buttonsWrapper.innerHTML = `
                        <button type="button" id="edit-photo-btn" class="photo-btn primary">Edit</button>
                        <button type="button" id="delete-photo-btn" class="photo-btn danger">Delete</button>`;
                    attachButtonListeners();
                    displayMessage(_('Photo updated!'), 'success', 'settings-message-container');
                } else {
                    displayMessage(data.message || _("Upload error."), 'error', 'settings-message-container');
                }
            } catch (error) {
                displayMessage(_('Network error.'), 'error', 'settings-message-container');
            }
        };

        const handleDelete = async () => {
            if (!confirm(_('Do you really want to delete your profile photo?'))) return;
            try {
                const response = await fetch('/api/user/profile-photo', {
                    method: 'DELETE',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() }
                });
                if (response.ok) {
                    const username = usernameInput.value;
                    previewWrapper.innerHTML = `
                        <div id="empty-avatar-placeholder" class="empty-avatar" style="cursor: pointer;">
                            <span>${username[0].toUpperCase()}</span>
                            <i class="fa-solid fa-camera" style="color: rgba(255,255,255,0.8); font-size: 1.2rem; margin-top: 0.5rem;"></i>
                            <p style="font-size: 0.8rem; margin-top: 0.2rem;">Add a photo</p>
                        </div>`;
                    buttonsWrapper.innerHTML = `<button type="button" id="add-photo-btn" class="photo-btn primary">Add a photo</button>`;
                    attachButtonListeners();
                    displayMessage(_('Photo deleted.'), 'success', 'settings-message-container');
                } else {
                    displayMessage(_('Error deleting.'), 'error', 'settings-message-container');
                }
            } catch (error) {
                displayMessage(_('Network error.'), 'error', 'settings-message-container');
            }
        };

        const attachButtonListeners = () => {
            const addBtn = document.getElementById('add-photo-btn');
            const editBtn = document.getElementById('edit-photo-btn');
            const deleteBtn = document.getElementById('delete-photo-btn');
            const placeholder = document.getElementById('empty-avatar-placeholder');
            if (addBtn) addBtn.addEventListener('click', () => photoFile.click());
            if (editBtn) editBtn.addEventListener('click', () => photoFile.click());
            if (deleteBtn) deleteBtn.addEventListener('click', handleDelete);
            if (placeholder) placeholder.addEventListener('click', () => photoFile.click());
        };

        attachButtonListeners();
        photoFile.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) handleUpload(file);
        });
    }

    // --- GESTION DU CHANGEMENT DE MOT DE PASSE ---
    const passwordForm = document.getElementById('password-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const current_password = document.getElementById('current-password').value;
            const new_password = document.getElementById('new-password').value;
            try {
                const response = await fetch('/api/user/change_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ current_password, new_password })
                });
                const data = await response.json();
                displayMessage(data.message, response.ok ? 'success' : 'error', 'settings-message-container');
                if (response.ok) {
                    passwordForm.reset();
                    closeModal(passwordModal);
                }
            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error', 'settings-message-container');
            }
        });
    }

    // --- GESTION DE LA DÉCONNEXION ---
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            if (confirm(_("Do you really want to log out?"))) {
                window.logout();
            }
        });
    }

    // --- GESTION DE LA SUPPRESSION DE COMPTE ---
    const deleteConfirmForm = document.getElementById('delete-confirm-form');
    if (deleteConfirmForm) {
        deleteConfirmForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('delete-password').value;
            try {
                const response = await fetch('/api/user/delete', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ password })
                });
                const data = await response.json();
                if (response.ok) {
                    alert(data.message);
                    window.location.href = '/';
                } else {
                    alert(_("Error: ") + data.message);
                }
            } catch (error) {
                alert(_('A network error occurred.'));
            }
        });
    }
});

<< ux_enhancer.js >>:  
document.addEventListener('DOMContentLoaded', () => {

    // --- GESTION DU PRELOADER ---
    const preloader = document.getElementById('preloader');

    // Cacher le preloader initial
    if (preloader) {
        window.addEventListener('load', () => {
            preloader.classList.add('hidden');
        });
    }

    // Afficher le preloader lors de la navigation
    document.body.addEventListener('click', (e) => {
        const link = e.target.closest('a');
        if (link) {
            const href = link.getAttribute('href');
            const target = link.getAttribute('target');
            // Condition pour ne pas déclencher sur les liens externes, les ancres, ou les actions JS
            if (href && (href.startsWith('/') || href.startsWith(window.location.origin)) && target !== '_blank' && !href.startsWith('#')) {
                // Ne pas déclencher pour les boutons d'action rapide comme les favoris
                if (!link.classList.contains('favorite-btn') && !link.closest('.no-loader')) {
                    if (preloader) {
                        preloader.classList.remove('hidden');
                    }
                }
            }
        }
    });
    window.addEventListener('pageshow', (event) => {
        if (event.persisted && preloader) {
            preloader.classList.add('hidden');
        }
    });

    // --- GESTION DU BOUTON "RETOUR EN HAUT" ---
    const backToTopButton = document.getElementById('back-to-top');

    if (backToTopButton) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 300) {
                backToTopButton.classList.add('show');
            } else {
                backToTopButton.classList.remove('show');
            }
        });

        backToTopButton.addEventListener('click', () => {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
    const imageModal = document.getElementById('image-viewer-modal');
    const alertModal = document.getElementById('alert-modal');
    const modalImageContent = document.getElementById('modal-image-content');
    const alertModalText = document.getElementById('alert-modal-text');

    // Fonction pour ouvrir une modale
    const openModal = (modal) => {
        if(modal) modal.classList.remove('hidden');
    };

    // Fonction pour fermer TOUTES les modales
    const closeModal = () => {
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.classList.add('hidden');
        });
    };

    // --- Écouteurs d'événements pour les clics ---
   // DANS static/js/ux_enhancer.js

// --- Écouteurs d'événements pour les clics (VERSION CORRIGÉE) ---
// DANS static/js/ux_enhancer.js

// --- Écouteurs d'événements pour les clics (VERSION FINALE CORRIGÉE) ---
// DANS static/js/ux_enhancer.js

// --- Écouteurs d'événements pour les clics (VERSION FINALE AVEC LOGIQUE PROPRIÉTAIRE) ---
document.body.addEventListener('click', (e) => {
    const alertModal = document.getElementById('alert-modal');
    if (!alertModal) return;

    // Clic sur une photo de profil dans une carte
    const avatarLink = e.target.closest('.author-avatar-link');
    if (avatarLink) {
        // ... (le code pour la modale photo reste le même)
        e.preventDefault();
        e.stopPropagation();
        const imageUrl = avatarLink.dataset.imgUrl;
        if (imageUrl && modalImageContent) {
            modalImageContent.src = imageUrl;
            openModal(imageModal);
        }
    }

     const interactiveItem = e.target.closest('.interactive-footer-item');
    if (interactiveItem) {
        e.stopPropagation();

        const message = interactiveItem.dataset.message;
        const authorId = interactiveItem.dataset.authorId;
        const postId = interactiveItem.dataset.postId;
        const currentUserId = document.body.dataset.userId;

        const alertModal = document.getElementById('alert-modal');
        const alertModalText = document.getElementById('alert-modal-text');
        const alertModalActions = document.getElementById('alert-modal-actions');

        if (message && alertModalText && alertModalActions) {
            alertModalText.textContent = message;
            alertModalActions.innerHTML = ''; // On vide les actions précédentes
            alertModalActions.classList.remove('center-actions'); // On retire la classe de centrage

            const isOwner = authorId && currentUserId && authorId === currentUserId;

            // Si ce n'est pas notre annonce, on ajoute le bouton "Contacter"
            if (authorId && postId && !isOwner) {
                const contactButton = document.createElement('button');
                contactButton.id = 'modal-contact-btn';
                contactButton.className = 'button-primary';
                // AJOUT DE L'ICÔNE ICI
                contactButton.innerHTML = `<i class="fa-solid fa-comment-dots"></i> ${ _('Contact by message') }`;
                contactButton.dataset.authorId = authorId;
                contactButton.dataset.postId = postId;
                alertModalActions.appendChild(contactButton);
            }

            // On ajoute toujours le bouton "OK"
            const okButton = document.createElement('button');
            okButton.className = 'button-secondary close-modal-btn-styled';
            okButton.textContent = _('OK');
            alertModalActions.appendChild(okButton);
            
            // Si le conteneur n'a qu'un seul bouton (le bouton "OK"), on le centre
            if (alertModalActions.childElementCount === 1) {
                alertModalActions.classList.add('center-actions');
            }

            openModal(alertModal);
        }
    }
    
    // Clic sur le bouton de contact DANS la modale
    const contactBtn = e.target.closest('#modal-contact-btn');
    if (contactBtn) {
        const authorId = contactBtn.dataset.authorId;
        const postId = contactBtn.dataset.postId;
        closeModal();
        handleStartChat(authorId, postId);
    }

    // Clic sur un bouton de fermeture ou sur le fond de la modale
    if (e.target.classList.contains('close-modal-btn') || e.target.classList.contains('close-modal-btn-styled') || e.target.classList.contains('modal-overlay')) {
        closeModal();
    }
});

async function handleStartChat(authorId, postId) {
    const csrfToken = window.getCsrfToken();
    if (!csrfToken) {
        window.location.href = '/login';
        return;
    }
    
    try {
        const response = await fetch('/api/chat/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken
            },
            body: JSON.stringify({
                participant_id: authorId,
                post_id: postId // On envoie l'ID du post
            })
        });
        const data = await response.json();
        if (data.success) {
            // Redirige vers la page de messagerie avec la bonne conversation
            window.location.href = `/messages?chatroom_id=${data.chatroom_id}`;
        } else {
            console.error('Failed to start chat:', data.message);
        }
    } catch (error) {
        console.error('Error starting chat:', error);
    }
}

    // Ajout d'un style pour le curseur sur les éléments interactifs
    const style = document.createElement('style');
    style.innerHTML = `.interactive-footer-item, .author-avatar-link { cursor: pointer; }`;
    document.head.appendChild(style);
});

<< manifest.json >>:  
{
  "short_name": "Business",
  "name": "Business",
  "icons": [
    {
      "src": "/static/images/favicon-192x192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any"
    },
    {
      "src": "/static/images/favicon-512x512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any"
    },
    {
      "src": "/static/images/logoB.png",
      "sizes": "96x96",
      "type": "image/png",
      "purpose": "monochrome"
    }
  ],
  "start_url": "/",
  "display": "standalone",
  "theme_color": "#0d6efd",
  "background_color": "#ffffff",
  "orientation": "portrait"
}


============
HTML COMPLET
============

<< actvate.html >>:  
<!DOCTYPE html>
<html lang="{{ get_locale() }}">
<head>
    <meta charset="UTF-8">
    <title>{{ _('Account Confirmation') }}</title>
    <style>
        body {
            font-family: 'Roboto', Arial, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
            color: #212529;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 1px solid #dee2e6;
            margin-bottom: 20px;
        }
        .header h1 {
            color: #0d6efd;
            margin: 0;
            font-size: 1.8rem;
        }
        .content {
            padding: 20px 0;
            color: #6c757d;
        }
        .content p {
            margin-bottom: 1rem;
        }
        .button-container {
            text-align: center;
            padding: 20px 0;
        }
        .button {
            background-color: #0d6efd;
            color: #ffffff;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            display: inline-block;
            transition: background-color 0.2s;
            font-size: 1rem;
        }
        .button:hover {
            background-color: #0b5ed7;
        }
        .link-text {
            color: #0d6efd;
            text-decoration: underline;
            word-break: break-all;
        }
        .footer {
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            font-size: 0.85rem;
            color: #6c757d;
        }
        @media (max-width: 600px) {
            .container { padding: 20px; }
            .header h1 { font-size: 1.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ _('Welcome to Business!') }}</h1>
        </div>
        <div class="content">
            <p>{{ _('Hello,') }}</p>
            <p>{{ _('Thank you for signing up. To activate your account and start exchanging, please click the button below:') }}</p>
        </div>
        <div class="button-container">
            <a href="{{ confirm_url }}" class="button">{{ _('Activate my account') }}</a>
        </div>
        <div class="content">
            <p>{{ _('If the button does not work, copy and paste the following link into your browser:') }}</p>
            <p><a href="{{ confirm_url }}" class="link-text">{{ confirm_url }}</a></p>
            <p><a href="{{ url_for('register_api', _external=True) }}" class="link-text">{{ _('Resend confirmation email') }}</a></p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Business. {{ _('All rights reserved.') }}</p>
        </div>
    </div>
</body>
</html>

<< reset_password.html >>:  
<!DOCTYPE html>
<html lang="{{ get_locale() }}">
<head>
    <meta charset="UTF-8">
    <title>{{ _('Password Reset Request') }}</title>
    <style>
        body {
            font-family: 'Roboto', Arial, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
            color: #212529;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 1px solid #dee2e6;
            margin-bottom: 20px;
        }
        .header h1 {
            color: #0d6efd;
            margin: 0;
            font-size: 1.8rem;
        }
        .content {
            padding: 20px 0;
            color: #6c757d;
        }
        .content p {
            margin-bottom: 1rem;
        }
        .button-container {
            text-align: center;
            padding: 20px 0;
        }
        .button {
            background-color: #0d6efd;
            color: #ffffff;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            display: inline-block;
            transition: background-color 0.2s;
            font-size: 1rem;
        }
        .button:hover {
            background-color: #0b5ed7;
        }
        .link-text {
            color: #0d6efd;
            text-decoration: underline;
            word-break: break-all;
        }
        .footer {
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            font-size: 0.85rem;
            color: #6c757d;
        }
        @media (max-width: 600px) {
            .container { padding: 20px; }
            .header h1 { font-size: 1.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ _('Password Reset Request') }}</h1>
        </div>
        <div class="content">
            <p>{{ _('Hello,') }}</p>
            <p>{{ _('We received a request to reset your password. Click the button below to continue. This link will expire in 15 minutes.') }}</p>
        </div>
        <div class="button-container">
            <a href="{{ reset_url }}" class="button">{{ _('Reset my password') }}</a>
        </div>
        <div class="content">
            <p>{{ _('If you did not make this request, you can safely ignore this email.') }}</p>
        </div>
        <div class="footer">
            <p>&copy; 2025 Business. {{ _('All rights reserved.') }}</p>
        </div>
    </div>
</body>
</html>

<< base.html >>:  
<!DOCTYPE html>
<html lang="{{ get_locale() }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Business{% endblock %}</title>
    
    <link rel="manifest" href="{{ url_for('manifest') }}">
    <link rel="apple-touch-icon" sizes="180x180" href="{{ url_for('static', filename='images/apple-touch-icon.png') }}">
    <link rel="icon" type="image/png" sizes="32x32" href="{{ url_for('static', filename='images/favicon-32x32.png') }}">
    <link rel="icon" type="image/png" sizes="16x16" href="{{ url_for('static', filename='images/favicon-16x16.png') }}">
    <meta name="theme-color" content="#0d6efd">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="Business">

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css"/>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/lightgallery/2.7.1/css/lightgallery.min.css" />

    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    
    {% block head_extra %}{% endblock %}
</head>
<body>
    <div id="preloader"><div class="spinner"></div></div>
    <div id="toast-container"></div>
    
    <header>
        <div class="container">
            <nav class="top-nav-level-1">
                <div class="top-bar-left">
                    <a href="{{ url_for('index_page') }}" class="logo-container">
                        <span class="logo-text">Business</span>
                    </a>
                    <label class="theme-switch" for="dark-mode-toggle" title="{{ _('Change theme') }}">
                        <input type="checkbox" id="dark-mode-toggle" />
                        <i class="fa-solid fa-moon moon-icon"></i>
                        <i class="fa-solid fa-sun sun-icon"></i>
                    </label>
                </div>
    
                <div class="top-bar-right">
    <div class="search-container" id="header-search-container">
        <div class="search-input-header-fake"></div>
        
        <button id="search-icon-btn" class="search-icon-btn" title="{{ _('Search') }}">
            <i class="fa-solid fa-magnifying-glass"></i>
        </button>
    </div>
    
                    {% if g.user %}
                        <div class="notification-menu">
                            <a href="{{ url_for('notifications_page') }}" class="notification-bell" title="{{ _('Notifications') }}">
                                <i class="fa-solid fa-bell"></i>
                            </a>
                        </div>
                        <div class="user-menu">
                            <button class="user-menu-button">
                                <i class="fa-solid fa-circle-user"></i>
                            </button>
                            <ul class="user-menu-dropdown">
                                <li><a href="{{ url_for('profile_page', username=g.user.username) }}"><i class="fa-solid fa-user fa-fw"></i> {{ _('Profile') }}</a></li>
                                <li><a href="{{ url_for('favorites_page') }}"><i class="fa-solid fa-bookmark fa-fw"></i> {{ _('My Favorites') }}</a></li>
                                <li><a href="{{ url_for('settings_page') }}"><i class="fa-solid fa-gear fa-fw"></i> {{ _('Settings') }}</a></li>
                                <li><a href="{{ url_for('help_page') }}"><i class="fa-solid fa-circle-question fa-fw"></i> {{ _('Help') }}</a></li>
                                <li class="separator"><a href="#" id="logout-button"><i class="fa-solid fa-right-from-bracket fa-fw"></i> {{ _('Logout') }}</a></li>
                            </ul>
                        </div>
                    {% else %}
                        <button class="icon-button" id="about-button" title="{{ _('About') }}">
                            <i class="fa-solid fa-circle-question"></i>
                        </button>
                        <div class="language-menu">
                            <button class="language-menu-button" title="{{ _('Change language') }}">
                                <i class="fa-solid fa-globe"></i>
                            </button>
                            <ul class="language-menu-dropdown">
                                <li><a href="#" class="lang-selector" data-lang="fr">Français</a></li>
                                <li><a href="#" class="lang-selector" data-lang="en">English</a></li>
                            </ul>
                        </div>
                    {% endif %}
                </div>
            </nav>
    
            <nav class="top-nav-level-2">
                {% if g.user %}
                    <a href="{{ url_for('index_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('Home') }}">
                        <i class="fa-solid fa-house-chimney"></i><span>{{ _('Home') }}</span>
                    </a>
                    <a href="{{ url_for('posts_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('Posts') }}">
                        <i class="fa-solid fa-th-large"></i><span>{{ _('Posts') }}</span>
                    </a>
                    <a href="{{ url_for('create_post_page') }}" class="desktop-nav-item mobile-nav-item nav-create-post create" title="{{ _('Create Post') }}">
                        <i class="fa-solid fa-plus-circle"></i><span class="create-span">{{ _('Create') }}</span>
                    </a>
                    <a href="{{ url_for('messages_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('Messages') }}">
                        <i class="fa-solid fa-comment-dots"></i><span>{{ _('Messages') }}</span>
                    </a>
                    <a href="{{ url_for('my_posts_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('My Posts') }}">
                        <i class="fa-solid fa-folder-open"></i><span>{{ _('My Posts') }}</span>
                    </a>
                {% else %}
                    <a href="{{ url_for('index_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('Home') }}">
                        <i class="fa-solid fa-house-chimney"></i><span>{{ _('Home') }}</span>
                    </a>
                    <a href="{{ url_for('register_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('Register') }}">
                        <i class="fa-solid fa-user-plus"></i><span>{{ _('Register') }}</span>
                    </a>
                    <a href="{{ url_for('login_page') }}" class="desktop-nav-item mobile-nav-item" title="{{ _('Login') }}">
                        <i class="fa-solid fa-right-to-bracket"></i><span>{{ _('Login') }}</span>
                    </a>
                {% endif %}
            </nav>
        </div>
    </header>

    <main class="container">
        {% block content %}{% endblock %}
    </main>

    <footer>
        <div  class="site-footer">
            <p>&copy; 2025 Business. {{ _('All rights reserved.') }}</p>
        </div>
    </footer>

    <button id="back-to-top" title="{{ _('Go to top') }}"><i class="fa-solid fa-arrow-up"></i></button>

    <div id="image-viewer-modal" class="modal-overlay hidden">
        <div class="modal-content-photo">
            <img id="modal-image-content" src="" alt="Aperçu de l'image">
        </div>
        <button class="close-modal-btn">&times;</button>
    </div>

    <div id="alert-modal" class="modal-overlay hidden">
    <div class="alert-modal-content">
        <div id="alert-modal-text"></div>
        <div id="alert-modal-actions" class="modal-actions">
            </div> 
    </div>
</div>

    <div id="about-modal" class="modal-overlay hidden">
        <div class="modal-content">
            <button class="close-modal-btn">&times;</button>
            <h3>{{ _('Welcome to Business!') }}</h3>
            <p>{{ _('Business is a local platform for exchange and sharing. Here, you can give a second life to your objects by exchanging them, or share your skills by offering services.') }}</p>
            <p>{{ _('To start interacting with the community, discover all the features, and post your own ads, creating an account is necessary. Join us!') }}</p>
            <div style="text-align: center; margin-top: 1.5rem;">
                <a href="{{ url_for('register_page') }}" class="button-primary">{{ _('Sign up for free') }}</a>
            </div>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lightgallery/2.7.1/lightgallery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
    
    <script>
        // Script de traduction
        window._ = function(text, vars) {
            let translated = text;
            if (vars) {
                for (const key in vars) {
                    translated = translated.replace(`%(${key})s`, vars[key]);
                }
            }
            return translated;
        };
        fetch('/api/translations')
            .then(res => res.json())
            .then(data => {
                window.translations = data;
                window._ = function(text, vars) {
                    let translated = window.translations[text] || text;
                    if (vars) {
                        for (const key in vars) {
                            translated = translated.replace(`%(${key})s`, vars[key]);
                        }
                    }
                    return translated;
                };
            })
            .catch(error => console.error("Could not load translations:", error));
    </script>
    <script src="{{ url_for('static', filename='js/auth_check.js') }}"></script>
    <script src="{{ url_for('static', filename='js/dark_mode.js') }}"></script>
    <script src="{{ url_for('static', filename='js/header_search.js') }}"></script>
    <script src="{{ url_for('static', filename='js/mobile_nav.js') }}"></script> 
    <script src="{{ url_for('static', filename='js/nav_active.js') }}"></script> 
    <script src="{{ url_for('static', filename='js/ux_enhancer.js') }}"></script>
    <script src="{{ url_for('static', filename='js/global_socket.js') }}"></script>
    
    {% if not g.user %}
    <script src="{{ url_for('static', filename='js/guest_nav.js') }}"></script>
    {% endif %}

    {% block scripts %}{% endblock %}

    <script>
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register("{{ url_for('service_worker') }}").then(reg => {
                    console.log('Service worker registered!', reg);
                }).catch(err => {
                    console.log('Service worker registration failed: ', err);
                });
            });
        }
    </script>
    
    {% if g.user %}
    <script>
        const VAPID_PUBLIC_KEY = "{{ config.VAPID_PUBLIC_KEY }}";
    </script>
    <script src="{{ url_for('static', filename='js/push-notifications.js') }}"></script>
    {% endif %}
</body>
</html>

<< create_post.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Create an ad') }} - Business{% endblock %}

{% block content %}
<div class="form-container modern-form">
    <h2>{{ _('Create your Ad') }}</h2>
    <p class="subtitle">{{ _('Follow the steps to publish your ad easily.') }}</p>
    
    <div id="message-container"></div>
    <form id="createPostForm">
        
        <fieldset class="form-step">
            <legend><span class="step-number">1</span> {{ _('Basic Information') }}</legend>
            <div class="form-group">
                <label for="title">{{ _('Ad title') }}</label>
                <input type="text" id="title" name="title" required placeholder="{{ _('Ex: Object exchange, gardening service...') }}">
            </div>
            <div class="form-group">
                <label for="description">{{ _('Detailed description') }}</label>
                <textarea id="description" name="description" rows="5" required placeholder="{{ _('Describe precisely what you are offering or looking for.') }}"></textarea>
            </div>
        </fieldset>

        <fieldset class="form-step">
            <legend><span class="step-number">2</span> {{ _('Category & Type') }}</legend>
            <div class="form-group-grid">
                <div class="form-group">
                    <label for="category-pills">{{ _('Category') }}</label>
                    <div id="category-pills" class="choice-pills">
                        <button type="button" class="pill-btn" data-category="Objet"><i class="fa-solid fa-box-open"></i> {{ _('Object') }}</button>
                        <button type="button" class="pill-btn" data-category="Service"><i class="fa-solid fa-handshake-angle"></i> {{ _('Service') }}</button>
                    </div>
                </div>
                 <div class="form-group">
                    <label for="type-pills">{{ _('Ad type') }}</label>
                    <div id="type-pills" class="choice-pills">
                        <button type="button" class="pill-btn" data-type="Offre"><i class="fa-solid fa-arrow-up-from-bracket"></i> {{ _('I offer') }}</button>
                        <button type="button" class="pill-btn" data-type="Demande"><i class="fa-solid fa-arrow-down-to-bracket"></i> {{ _('I request') }}</button>
                    </div>
                </div>
            </div>
        </fieldset>

        <fieldset class="form-step">
            <legend><span class="step-number">3</span> {{ _('Add Photos') }}</legend>
            <div class="form-group">
                <label for="file" class="upload-area">
                    <i class="fa-solid fa-cloud-arrow-up fa-2x"></i>
                    <p><strong>{{ _('Click here') }}</strong> {{ _('or drag and drop images') }}</p>
                    <span class="form-hint">{{ _('The first image will be the cover.') }}</span>
                </label>
                <input type="file" id="file" name="file" accept="image/*" multiple style="display: none;">
                <div id="image-preview-container" class="image-preview-container"></div>
            </div>
        </fieldset>
        
        <fieldset class="form-step">
            <legend><span class="step-number">4</span> {{ _('Location') }}</legend>
            <div class="form-group">
                <label for="location-selector">{{ _('Department(s) concerned') }}</label>
                <p class="form-hint">{{ _('You can select multiple departments.') }}</p>
                <select id="location-selector" name="location" required multiple></select>
            </div>
        </fieldset>

        <button type="submit" class="button-primary submit-btn-large">{{ _('Publish my Ad') }} <i class="fa-solid fa-rocket"></i></button>
    </form>
</div>
{% endblock %}

{% block scripts %}
<script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css" />
<script src="{{ url_for('static', filename='js/geolocation.js') }}"></script>
<script src="{{ url_for('static', filename='js/create_post.js') }}"></script>
{% endblock %}

<< edit_post.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Modify an ad') }} - Business{% endblock %}

{% block content %}
<div class="form-container">
    <h2>{{ _('Modify the ad') }}</h2>
    <div id="message-container"></div>
    <form id="editPostForm">
        <input type="hidden" id="postId" value="{{ post_id }}">
        
        <div class="form-group">
            <label for="title">{{ _('Title') }}</label>
            <input type="text" id="title" name="title" required>
        </div>
        
        <div class="form-group">
            <label for="description">{{ _('Description') }}</label>
            <textarea id="description" name="description" rows="6" required></textarea>
        </div>
        
        <div class="form-group">
            <label for="type">{{ _('Type of ad') }}</label>
            <select id="type" name="type" required>
                <option value="Offre">{{ _('I offer') }}</option>
                <option value="Demande">{{ _('I request') }}</option>
            </select>
        </div>
        
        <div class="form-group">
            <label for="category">{{ _('Category') }}</label>
            <select id="category" name="category" required>
                <option value="Objet">{{ _('Object') }}</option>
                <option value="Service">{{ _('Service') }}</option>
            </select>
        </div>

        <div class="form-group">
            <label>{{ _('Current image') }}</label>
            <div id="image-preview-container" class="image-preview-container">
                </div>
                <div class="form-group">
    <label for="file">{{ _('Image(s)') }}</label>
    <input type="file" id="file" name="file" accept="image/*" multiple>
    <div id="image-preview-container" class="image-preview-container"></div>
</div>
            <label for="file">{{ _('Change or add an image') }}</label>
            <input type="file" id="file" name="file" accept="image/*" multiple>
        </div>
        <div class="form-group">
    <label for="location-selector">{{ _('Ad Location(s)') }}</label>
    <select id="location-selector" name="location" required multiple></select>
</div>
        
        <button type="submit" class="button-primary">{{ _('Update the ad') }}</button>
    </form>
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/geolocation.js') }}"></script>
<script src="{{ url_for('static', filename='js/edit_post.js') }}"></script>
{% endblock %}

<< favorites.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('My Favorites') }} - Business{% endblock %}

{% block content %}
<div class="page-header">
    <h2>{{ _('My Favorites') }}</h2>
    <div class="actions-menu">
        <button class="actions-button">
            <i class="fa-solid fa-ellipsis-vertical"></i>
        </button>
        <div class="actions-dropdown">
            <button id="clear-favorites-button" class="dropdown-item danger"><i class="fa-solid fa-trash"></i> {{ _('Clear the list') }}</button>
        </div>
    </div>
</div>

<div id="message-container"></div>
<div id="favorites-list-container" class="posts-grid">
    <!-- Les favoris sont chargés ici -->
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/favorites.js') }}"></script>
{% endblock %}

<< forgot_password.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Forgot password') }} - Troquez-Ici{% endblock %}

{% block content %}
<div class="form-container">
    <h2>{{ _('Reset the password') }}</h2>
    <p>{{ _('Enter your email address and we will send you a link to reset your password.') }}</p>
    <div id="message-container"></div>
    <form id="forgotPasswordForm">
        <div class="form-group">
            <label for="email">{{ _('Email address') }}</label>
            <input type="email" id="email" name="email" required>
        </div>
        <button type="submit" class="button-primary">{{ _('Send the reset link') }}</button>
    </form>
     <p class="form-footer-text"><a href="{{ url_for('login_page') }}">{{ _('Back to login') }}</a></p>
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/forgot_password.js') }}"></script>
{% endblock %}

<< help.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Help Center') }} - Business{% endblock %}

{% block content %}
<div class="static-page-container">
    <h1><i class="fa-solid fa-circle-question"></i> {{ _('Help Center') }}</h1>
    <p class="subtitle">{{ _('Welcome to the Business usage guide. Find here all the answers to your questions.') }}</p>

    <nav class="toc">
        <h3>{{ _('Table of contents') }}</h3>
        <ul>
            <li><a href="#section-1">{{ _('1. First Steps on Business') }}</a></li>
            <li><a href="#section-2">{{ _('2. Posting and Managing Your Ads') }}</a></li>
            <li><a href="#section-3">{{ _('3. Interacting with the Community') }}</a></li>
            <li><a href="#section-4">{{ _('4. Using Private Messaging') }}</a></li>
            <li><a href="#section-5">{{ _('5. Managing Your Account and Settings') }}</a></li>
            <li><a href="#section-6">{{ _('6. For Visitors (Without an Account)') }}</a></li>
        </ul>
    </nav>

    <section id="section-1" class="help-section">
        <h2>{{ _('1. First Steps on Business') }}</h2>
        <h3><i class="fa-solid fa-user-plus"></i> {{ _('Create an account and log in') }}</h3>
        <p>{{ _('To enjoy all features, you must first create an account. Click on "Register" in the navigation bar. Fill in the form with a username, a valid email address, and a secure password (at least 6 characters, including an uppercase letter, a lowercase letter, and a digit). A confirmation email will be sent to you to activate your account.') }}</p>
        <p>{{ _('Once your account is activated, you can log in via the "Login" page. You will then be prompted to add a profile picture, which you can do immediately or ignore to do it later.') }}</p>
    </section>

    <section id="section-2" class="help-section">
        <h2>{{ _('2. Posting and Managing Your Ads') }}</h2>
        <h3><i class="fa-solid fa-circle-plus"></i> {{ _('Create an ad') }}</h3>
        <p>{{ _('Click on the "Create" icon. You will first have to choose if you want to post a <strong>Service</strong> or an <strong>Object</strong>. Then fill in the form by giving a clear title, a detailed description, and specifying if it is an <strong>Offer</strong> (you provide) or a <strong>Request</strong> (you are looking for). You can add several photos to your ad and select multiple locations.') }}</p>
        
        <h3><i class="fa-solid fa-folder-open"></i> {{ _('Manage "My Ads"') }}</h3>
        <p>{{ _('This section groups all the ads you have published. For each ad, you can:') }}</p>
        <ul>
            <li><strong>{{ _('Hide/Show:') }}</strong> {{ _('Use the <i class="fa-solid fa-eye"></i> or <i class="fa-solid fa-eye-slash"></i> button to make an ad temporarily invisible or visible to other users.') }}</li>
            <li><strong>{{ _('Edit:') }}</strong> {{ _('The <i class="fa-solid fa-pen-to-square"></i> button opens the editing form to change the title, description, or photos.') }}</li>
            <li><strong>{{ _('Delete:') }}</strong> {{ _('The <i class="fa-solid fa-trash"></i> button permanently deletes the ad.') }}</li>
            <li><strong>{{ _('Multiple Selection:') }}</strong> {{ _('Press and hold an ad on mobile (or use the options menu <i class="fa-solid fa-ellipsis-vertical"></i> at the top right) to select multiple ads and perform bulk actions (hide, show, delete all).') }}</li>
        </ul>
    </section>

    <section id="section-3" class="help-section">
        <h2>{{ _('3. Interacting with the Community') }}</h2>
        <h3><i class="fa-solid fa-magnifying-glass"></i> {{ _('Browsing and Filtering Ads') }}</h3>
        <p>{{ _('On the "Ads" page, you can search for a specific term, filter by type (Offers/Requests), by category (Objects/Services), by location, and sort the results (Newest/Oldest).') }}</p>
        
        <h3><i class="fa-solid fa-bookmark"></i> {{ _('Favorites') }}</h3>
        <p>{{ _('Click on the bookmark icon on an ad card to add it to your "My Favorites" page. This allows you to easily find it later.') }}</p>

        <h3><i class="fa-solid fa-star"></i> {{ _('Understanding a User Profile') }}</h3>
        <p>{{ _('By clicking on a user\'s name, you access their profile where you can find:') }}</p>
        <ul>
            <li><strong>{{ _('Average Rating:') }}</strong> {{ _('The average of the ratings (out of 5 stars) left by other users.') }}</li>
            <li><strong>{{ _('Interactions:') }}</strong> {{ _('The total number of interests accumulated on all their ads. It reflects their activity and the attractiveness of what they offer on the platform.') }}</li>
            <li><strong>{{ _('Their active ads:') }}</strong> {{ _('A list of all the ads currently published by that user.') }}</li>
        </ul>
    </section>
    
    <section id="section-4" class="help-section">
        <h2>{{ _('4. Using Private Messaging') }}</h2>
        <p>{{ _('Messaging allows you to chat privately and securely with other users.') }}</p>
        <h3><i class="fa-solid fa-paper-plane"></i> {{ _('Start a conversation') }}</h3>
        <p>{{ _('To contact a user, go to one of their ads and click on the "Contact by Chat" button. This will create a new conversation in your messaging and increase the ad\'s interest count by one.') }}</p>
        <h3><i class="fa-solid fa-toolbox"></i> {{ _('Features') }}</h3>
        <ul>
            <li><strong>{{ _('Text, voice, and files:') }}</strong> {{ _('You can send written messages, record voice notes by holding the microphone icon <i class="fa-solid fa-microphone"></i>, or attach image files with the paperclip icon <i class="fa-solid fa-paperclip"></i>.') }}</li>
            <li><strong>{{ _('Reply to a message:') }}</strong> {{ _('Hover over (or tap on) a message to display a reply icon <i class="fa-solid fa-reply"></i>. Click on it to quote this message in your response.') }}</li>
            <li><strong>{{ _('Rate a user:') }}</strong> {{ _('After an interaction, you can leave a rating for your interlocutor using the "Rate" button at the top of the conversation.') }}</li>
            <li><strong>{{ _('Message Status:') }}</strong> {{ _('A single check <i class="fa-solid fa-check"></i> means sent. Two gray checks <i class="fa-solid fa-check-double"></i> mean delivered. Two blue checks mean read.') }}</li>
        </ul>
    </section>

    <section id="section-5" class="help-section">
        <h2>{{ _('5. Managing Your Account and Settings') }}</h2>
        <h3><i class="fa-solid fa-gear"></i> {{ _('The Settings page') }}</h3>
        <p>{{ _('Accessible from the user menu, the "Settings" page allows you to control your account. You can:') }}</p>
        <ul>
            <li><strong>{{ _('Language:') }}</strong> {{ _('Change the application language. This choice will be saved for your future visits.') }}</li>
            <li><strong>{{ _('Theme:') }}</strong> {{ _('Switch between light and dark themes using the sun/moon icon in the top navigation bar.') }}</li>
            <li>{{ _('Modify your username, email, and profile picture.') }}</li>
            <li>{{ _('Change your password.') }}</li>
            <li>{{ _('Log out.') }}</li>
            <li>{{ _('Permanently delete your account (warning, this action is irreversible).') }}</li>
        </ul>
    </section>

    <section id="section-6" class="help-section">
        <h2>{{ _('6. For Visitors (Without an Account)') }}</h2>
        <h3><i class="fa-solid fa-binoculars"></i> {{ _('Discovering the Platform') }}</h3>
        <p>{{ _('Even without an account, you can browse the latest ads. In the navigation bar, you will find an "About" icon (?) that explains the concept of the application and a globe icon to change the display language.') }}</p>
        <h3>{{ _('Why Register?') }}</h3>
        <p>{{ _('Registration is free and necessary to unlock all features: contact other members, post your own ads, save your favorites, and much more.') }}</p>
    </section>
</div>
{% endblock %}

<< index.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Home') }} - Business{% endblock %}

{% block content %}
<div class="hero-section">
    <h1>{{ _('Exchanges, Share, Discover.') }}</h1>
    <p>{{ _('Give a second life to your objects and share your services with a benevolent local community.') }}</p>
    <a href="{{ url_for('posts_page') }}" class="button-primary">{{ _('See all ads') }}</a>
</div>

<div class="page-header">
    <h2>{{ _('Last Ads') }}</h2>
    <div class="modern-search-bar homepage-search">
        <i class="fa-solid fa-search"></i>
        <input type="search" id="search-input" placeholder="{{ _('What are you looking for today?') }}">
    </div>
</div>

<div id="message-container"></div>
<div id="posts-list-container" class="posts-grid">
    {% if latest_posts %}
    {% for post in latest_posts %}
        <div class="post-card">
            
            {% set favoritedClass = 'favorited' if g.user and post in g.user.favorite_posts else '' %}
            <button class="favorite-btn {{ favoritedClass }}" data-post-id="{{ post.id }}" title="{{ _('Save') }}">
                <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
            </button>
            
            <a href="{{ url_for('post_detail_page', post_id=post.id) }}" class="post-card-link">
                {% if post.images %}
                <div class="post-card-image" style="background-image: url({{ url_for('uploaded_file', filename=post.images[0].file_path) }});"></div>
                {% endif %}
                <div class="post-card-content">
                    <span class="post-card-category category-{{ post.category|lower }}">
                        {{ post.category }}
                    </span>
                    <h3>{{ post.title }}</h3>
                    {% if post.locations %}
    <div class="post-card-location">
        <i class="fa-solid fa-map-marker-alt"></i>
        <span>{{ post.locations|map(attribute='name')|join(', ') }}</span>
    </div>
    {% endif %}
                </div>
            </a>
            <div class="post-card-footer-new">
                <div class="footer-left">
                    {% if post.author.profile_photo %}
                        <a href="#" class="author-avatar-link" data-img-url="{{ url_for('uploaded_file', filename=post.author.profile_photo) }}" title="Voir la photo">
                            <img src="{{ url_for('uploaded_file', filename=post.author.profile_photo) }}" class="author-photo-small">
                        </a>
                    {% else %}
                        <div class="author-initial-small">{{ post.author.username[0]|upper }}</div>
                    {% endif %}
                    <a href="{{ url_for('profile_page', username=post.author.username, from_post=post.id) }}" title="Voir le profil">{{ post.author.username }}</a>
                </div>
                
<div class="footer-center interactive-footer-item" 
         data-message="{{ _('%(count)s people interact with this ad.', count=post.interest_count) }}" 
         data-author-id="{{ post.user_id }}" 
         data-post-id="{{ post.id }}" 
         title="Voir les interactions">
        <i class="fa-solid fa-comments"></i>
        <span>{{ post.interest_count }}</span>
    </div>

    <div class="footer-right interactive-footer-item" 
         data-message="{{ _('This ad has been viewed %(count)s times.', count=post.view_count) }}" 
         title="Voir les vues">
        <i class="fa-solid fa-eye"></i>
        <span>{{ post.view_count }}</span>
    </div>
</div>
            </div>
        </div>
    {% endfor %}
{% else %}
    <p>{{ _('No ad for the moment. Be the first to create one!') }}</p>
{% endif %}
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/home.js') }}"></script>
{% endblock %}

<< login.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Log in') }} - Troquez-Ici{% endblock %}

{% block content %}
<div class="form-container">
    <h2>{{ _('Log in') }}</h2>
    <p>{{ _('Happy to see you again!') }}</p>
    <div id="message-container"></div>
    <form id="loginForm">
        <div class="form-group">
            <label for="email">{{ _('Email address') }}</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="password">{{ _('Password') }}</label>
            <input type="password" id="password" name="password" required>
        </div>
        <div class="form-extra-links">
            <a href="{{ url_for('forgot_password_page') }}">{{ _('Forgot password?') }}</a>
        </div>
        <button type="submit" class="button-primary">{{ _('Log in') }}</button>
    </form>
    <p class="form-footer-text">{{ _('Not an account yet?') }} <a href="{{ url_for('register_page') }}">{{ _('Sign up here') }}</a>.</p>
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/login.js') }}"></script>
<script>
document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('message');

    if (message === 'confirmed') {
        displayMessage('{{ _("Your account has been successfully confirmed! You can now log in.") }}', 'success');
    } else if (message === 'already_confirmed') {
        displayMessage('{{ _("Your account has already been confirmed. You can log in.") }}', 'info');
    } else if (message === 'password_reset_success') {
        displayMessage('{{ _("Your password has been successfully reset.") }}', 'success');
    }
});
</script>
{% endblock %}

<< messages.html >>:  
{% extends "base.html" %}
{% block body_class %}messages-page{% endblock %}
{% block title %}{{ _('Mes Messages') }} - Business{% endblock %}

{% block head_extra %}
    <link rel="stylesheet" href="{{ url_for('static', filename='css/messages.css') }}">
    <script type="module" src="https://cdn.jsdelivr.net/npm/emoji-picker-element@^1/index.js"></script>
{% endblock %}

{% block content %}
<div class="page-wrapper-chat">
    <div class="chat-container">
        <aside id="chat-list-panel" class="chat-list-panel">
            <div class="chat-list-header">
                <h2>{{ _('Conversations') }}</h2>
            </div>
            <div id="chatrooms-list" class="chat-list-body">
                </div>
        </aside>

        <main id="chat-area-panel" class="chat-area-panel">
            <div id="chat-welcome-screen" class="chat-welcome-screen">
                <i class="fa-solid fa-comments welcome-icon"></i>
                <h3>{{ _('Votre messagerie') }}</h3>
                <p>{{ _("Sélectionnez une conversation pour commencer.") }}</p>
            </div>

            <div id="chat-main-screen" class="chat-main-screen hidden">
                <header id="current-chat-header" class="chat-area-header"></header>
                <div id="messages-display" class="messages-display"></div>
                
                <footer id="message-input-area" class="message-input-area">
                    <div id="reply-preview-container" class="reply-preview-container hidden">
                        <div class="reply-preview-content"></div>
                        <button id="cancel-reply-btn" class="cancel-reply-btn" title="{{ _('Annuler la réponse') }}">&times;</button>
                    </div>

                    <div class="input-mode-text">
                        </div>

                    <div class="input-mode-voice">
                        </div>
    <div class="input-mode-text">
        <div class="text-input-wrapper">
            <button id="emoji-button" class="chat-icon-button" title="{{ _('Émojis') }}"><i class="fa-solid fa-smile"></i></button>
            <textarea id="message-input" placeholder="{{ _('Message') }}" rows="1"></textarea>
            <button id="attach-file-button" class="chat-icon-button" title="{{ _('Joindre un fichier') }}"><i class="fa-solid fa-paperclip"></i></button>
            </div>

        <button id="mic-or-send-btn" class="chat-icon-button mic-mode" title="{{ _('Message vocal') }}">
            <i class="fa-solid fa-microphone"></i>
        </button>
    </div>

    <div class="input-mode-voice">
    <div class="voice-recorder-top">
        <span id="record-timer">0:00</span>
        <div id="waveform-container">
            </div>
    </div>
    <div class="voice-recorder-bottom">
        <button id="cancel-voice-btn" class="voice-action-btn" title="{{ _('Annuler') }}">
            <i class="fa-solid fa-trash"></i>
        </button>
        <button id="pause-resume-btn" class="voice-action-btn pause-btn" title="{{ _('Mettre en pause') }}">
            <i class="fa-solid fa-pause"></i>
        </button>
        <button id="voice-send-btn" class="voice-action-btn send-btn" title="{{ _('Envoyer') }}">
            <i class="fa-solid fa-paper-plane"></i>
        </button>
    </div>
</div>

    <div id="attachment-popup" class="attachment-popup">
        <button class="attachment-option" data-action="gallery">
            <i class="fa-solid fa-images"></i> <span>{{ _('Galerie') }}</span>
        </button>
        <button class="attachment-option" data-action="camera">
            <i class="fa-solid fa-camera"></i> <span>{{ _('Appareil photo') }}</span>
        </button>
        <button class="attachment-option" data-action="document">
            <i class="fa-solid fa-file-alt"></i> <span>{{ _('Document') }}</span>
        </button>
    </div>
    <div style="display: none;">
    <input type="file" id="gallery-input" accept="image/*,video/*" multiple> 
    <input type="file" id="camera-input" accept="image/*" capture="environment"> 
    <input type="file" id="document-input" accept=".pdf,.doc,.docx,.txt,.xls,.xlsx,.ppt,.pptx" multiple>
    
</div>
</footer>

            </div>
        </main>
    </div>
</div>

<div id="rating-modal" class="modal-overlay hidden">
    <div class="modal-content">
        <button class="close-modal-btn">&times;</button>
        <h3>{{ _('Rate the user') }}</h3>
        <p>{{ _('What rating would you give to') }} <strong id="rated-username"></strong> ?</p>
        <form id="rating-form">
            <div class="star-rating">
                <span class="star" data-value="1"><i class="fa-regular fa-star"></i></span>
                <span class="star" data-value="2"><i class="fa-regular fa-star"></i></span>
                <span class="star" data-value="3"><i class="fa-regular fa-star"></i></span>
                <span class="star" data-value="4"><i class="fa-regular fa-star"></i></span>
                <span class="star" data-value="5"><i class="fa-regular fa-star"></i></span>
            </div>
            <input type="hidden" id="rating-value" name="stars" value="0">
            <div class="form-group">
                <label for="rating-comment">{{ _('Add a comment (optional)') }}</label>
                <textarea id="rating-comment" name="comment" rows="3"></textarea>
            </div>
            <button type="submit" class="button-primary">{{ _('Send the evaluation') }}</button>
        </form>
    </div>    
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/messages.js') }}"></script>
{% endblock %}

<< my_posts.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('My ads') }} - Business{% endblock %}

{% block content %}
<div class="page-content-wrapper">

    <div class="page-header">
        <h2>{{ _('My ads') }}</h2>
        
        <div class="main-actions-menu">
            <button id="main-actions-button" class="actions-button" title="{{ _('Actions') }}">
                <i class="fa-solid fa-ellipsis-vertical"></i>
            </button>
            <div id="main-actions-dropdown" class="actions-dropdown">
                <!-- Le contenu est généré par JS -->
            </div>
        </div>
    </div>

    <div id="message-container"></div>

    <div id="my-posts-list-container" class="posts-grid">
        <!-- Les annonces sont chargées ici par JS -->
    </div>

</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/my_posts.js') }}"></script>
{% endblock %}

<< notifications.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Notifications') }} - Business{% endblock %}

{% block content %}
<div class="page-header">
    <h2>{{ _('Notifications') }}</h2>
    
    <div class="main-actions-menu">
        <button id="main-actions-button" class="actions-button" title="{{ _('Actions') }}">
            <i class="fa-solid fa-ellipsis-vertical"></i>
        </button>
        <div id="main-actions-dropdown" class="actions-dropdown">
            </div>
    </div>
    </div>

<div id="message-container"></div>
<div id="notifications-list-container" class="notifications-list">
    </div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/notifications.js') }}"></script>
{% endblock %}

<< post_detail.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Details of the ad') }} - Troquez-Ici{% endblock %}
{% block head_extra %}
<link rel="stylesheet" href="https://unpkg.com/swiper/swiper-bundle.min.css" />
<style>
    .swiper-button-next, .swiper-button-prev { color: var(--primary-color); }
    .swiper-pagination-bullet-active { background: var(--primary-color); }
</style>
{% endblock %}

{% block content %}
<div id="message-container"></div>
<div class="post-detail-container">
    </div>
{% endblock %}

{% block scripts %}
<script>
    const POST_ID = "{{ post_id }}";
</script>
<script src="{{ url_for('static', filename='js/post_detail.js') }}"></script>
{% endblock %}

<< posts.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('All ads') }} - Troquez-Ici{% endblock %}

{% block content %}
<div class="page-header">
    <h2>{{ _('All Ads') }}</h2>
    
    <div class="modern-search-bar">
        <i class="fa-solid fa-search"></i>
        <input type="search" id="search-input" placeholder="{{ _('Search for an object or service...') }}">
    </div>
</div>
<div class="filters-and-nav-container">
    <div class="filters-bar-new">
        <div class="filter-group">
            <i class="fa-solid fa-filter"></i>
            <select id="type-filter">
                <option value="">{{ _('Type (All)') }}</option>
                <option value="Offre">{{ _('Offers') }}</option>
                <option value="Demande">{{ _('Requests') }}</option>
            </select>
        </div>
        <div class="filter-group">
            <i class="fa-solid fa-sort-amount-down"></i>
            <select id="sort-filter">
                <option value="newest">{{ _('Sort: Newest') }}</option>
                <option value="oldest">{{ _('Sort: Oldest') }}</option>
            </select>
        </div>
        
    <div class="filter-group">
    <i class="fa-solid fa-map-marker-alt"></i>
    <select id="location-filter" multiple></select>
</div>
    </div>

    <div class="category-nav">
        <button class="category-nav-item active" data-category="">
            <i class="fa-solid fa-grip"></i>
            <span>{{ _('All') }}</span>
        </button>
        <button class="category-nav-item" data-category="Service">
            <i class="fa-solid fa-handshake-angle"></i>
            <span>{{ _('Services') }}</span>
        </button>
        <button class="category-nav-item" data-category="Objet">
            <i class="fa-solid fa-box-open"></i>
            <span>{{ _('Objects') }}</span>
        </button>
    </div>
</div>

<div id="message-container"></div>
<div id="posts-list-container" class="posts-grid">
    </div>
{% endblock %}

{% block scripts %}
<script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css" />
<script src="{{ url_for('static', filename='js/geolocation.js') }}"></script>

<script src="{{ url_for('static', filename='js/posts.js') }}"></script>
{% endblock %}

<< profile.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Profile of') }} {{ profile_user.username }}{% endblock %}

{% block head_extra %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/profile.css') }}">
{% endblock %}

{% block content %}
<div class="profile-container">
    <div id="message-container"></div>
    <div class="profile-header">
       <div class="profile-avatar">
            {% if profile_user.profile_photo %}
                <img src="{{ url_for('uploaded_file', filename=profile_user.profile_photo) }}" 
                     alt="Photo de profil de {{ profile_user.username }}" 
                     class="profile-photo-clickable">
            {% else %}
                <span class="profile-initial">{{ profile_user.username[0]|upper }}</span>
            {% endif %}
        </div>
        <div class="profile-info">
            <h1>{{ profile_user.username }}</h1>
            <p>{{ _('Member since') }} {{ profile_user.member_since.strftime('%d %B %Y') }}</p>
            
            <div class="profile-stats">
                <div class="profile-rating">
                    <div class="stars">
                        {% for i in range(5) %}
                            <span class="star {% if i < avg_rating|round|int %}filled{% endif %}">?</span>
                        {% endfor %}
                    </div>
                    <span class="rating-text">{{ avg_rating }} {{ _('on') }} 5 ({{ rating_count }} {{ _('reviews') }})</span>
                </div>
                <div class="profile-interest">
    <i class="fa-solid fa-comments"></i>
    
    <span>{{ total_interest }} {{ _('interactions') }}</span> 
</div>
            </div>
            
            {% if g.user and g.user.id == profile_user.id %}
                <p class="profile-email">{{ profile_user.email }}</p>
            {% else %}
                <button id="chat-button" class="button-primary" 
                    data-author-id="{{ profile_user.id }}" 
                    {% if from_post_id %}data-post-id="{{ from_post_id }}"{% endif %}>
                    {{ _('Contact by Chat') }}
                </button>
            {% endif %}
        </div>
    </div>

    <div class="profile-content">
        <h2>{{ _('Ads of') }} {{ profile_user.username }}</h2>
        <div id="posts-list-container" class="posts-grid">
            {% if posts %}
                {% for post in posts %}
                <div class="post-card">
                    <button class="favorite-btn {% if g.user and post in g.user.favorite_posts %}favorited{% endif %}" data-post-id="{{ post.id }}" title="{{ _('Save') }}">
                        <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
                    </button>
                    <a href="{{ url_for('post_detail_page', post_id=post.id) }}" class="post-card-link">
                        {% if post.images %}
                            <div class="post-card-image" style="background-image: url({{ url_for('uploaded_file', filename=post.images[0].file_path) }});"></div>
                        {% endif %}
                        <div class="post-card-content">
                            <span class="post-card-category category-{{ post.category|lower }}">
                                {{ post.category }}
                            </span>
                            <h3>{{ post.title }}</h3>
                        </div>
                        <div class="post-card-footer-new">
                            <div class="footer-left">
                                {% if post.author.profile_photo %}
                                    <img src="{{ url_for('uploaded_file', filename=post.author.profile_photo) }}" class="author-photo-small">
                                {% else %}
                                    <div class="author-initial-small">{{ post.author.username[0]|upper }}</div>
                                {% endif %}
                                <span>{{ post.author.username }}</span>
                            </div>
                            <div class="footer-center">
    <i class="fa-solid fa-comments"></i>
    
    <span>{{ post.interest_count }}</span> 
</div>
                            <div class="footer-right">
                                <i class="fa-solid fa-eye"></i>
                                <span>{{ post.view_count }}</span>
                            </div>
                        </div>
                    </a>
                </div>
                {% endfor %}
            {% else %}
                <p>{{ profile_user.username }} {{ _('has not published any ad yet.') }}</p>
            {% endif %}
        </div>
    </div>
</div>

<div class="profile-reviews-container">
    <h3>{{ _('Received ratings') }} ({{ rating_count }})</h3>
    {% if ratings %}
        <div class="reviews-list">
            {% for rating in ratings %}
                <div class="review-card">
                    <div class="review-author">
                        <div class="author-avatar">
                            {% if rating.rater.profile_photo %}
                                <img src="{{ url_for('uploaded_file', filename=rating.rater.profile_photo) }}" class="author-photo-small" style="width:100%; height:100%;">
                            {% else %}
                                <span>{{ rating.rater.username[0]|upper }}</span>
                            {% endif %}
                        </div>
                        <div class="author-info">
                            <strong><a href="{{ url_for('profile_page', username=rating.rater.username) }}">{{ rating.rater.username }}</a></strong>
                            <span class="review-date">{{ rating.timestamp.strftime('%d %B %Y') }}</span>
                        </div>
                    </div>
                    <div class="review-content">
                        <div class="review-stars">
                            {% for i in range(5) %}
                                <span class="star {% if i < rating.stars %}filled{% endif %}">?</span>
                            {% endfor %}
                        </div>
                        {% if rating.comment %}
                            <p class="review-comment">{{ rating.comment }}</p>
                        {% endif %}
                    </div>
                </div>
            {% endfor %}
        </div>
    {% else %}
        <p>{{ profile_user.username }} {{ _('has not received any rating yet.') }}</p>
    {% endif %}
</div>

<div id="photo-modal" class="modal-overlay hidden">
    <button class="close-modal-btn">&times;</button>
    <div class="modal-content-photo">
        <img id="modal-image" src="" alt="Photo de profil en grand">
    </div>
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/profile.js') }}"></script>
{% endblock %}

<< register.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Create an account') }} - Troquez-Ici{% endblock %}

{% block content %}
<div class="form-container">
    <h2>{{ _('Create an account') }}</h2>
    <p>{{ _('Join our exchange and sharing community.') }}</p>
    <div id="message-container"></div>
    <form id="registerForm">
        <div class="form-group">
            <label for="username">{{ _('Username') }}</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="email">{{ _('Email address') }}</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="password">{{ _('Password') }}</label>
            <input type="password" id="password" name="password" required>
            
            <div id="password-rules" class="password-rules">
                <div id="length-rule" class="rule invalid">{{ _('At least 6 characters') }}</div>
                <div id="lower-rule" class="rule invalid">{{ _('One lowercase letter') }}</div>
                <div id="upper-rule" class="rule invalid">{{ _('One uppercase letter') }}</div>
                <div id="number-rule" class="rule invalid">{{ _('One digit') }}</div>
            </div>
        </div>
        <div class="form-group">
            <label for="confirm_password">{{ _('Confirm the password') }}</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        <div class="form-group">
    <label for="location">{{ _('Your Department') }}</label>
    <select id="location-selector" name="location"></select>
</div>

{% block scripts %}
<script src="{{ url_for('static', filename='js/geolocation.js') }}"></script>
<script src="{{ url_for('static', filename='js/register.js') }}"></script>
{% endblock %}
        <button type="submit" class="button-primary">{{ _('Sign up') }}</button>
    </form>
    <p class="form-footer-text">{{ _('Already have an account?') }} <a href="{{ url_for('login_page') }}">{{ _('Log in here') }}</a>.</p>
</div>
{% endblock %}

<< reset_password.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Reset the password') }} - Troquez-Ici{% endblock %}

{% block content %}
<div class="form-container">
    <h2>{{ _('Choose a new password') }}</h2>
    <p>{{ _('Please enter your new password below.') }}</p>
    <div id="message-container"></div>
    <form id="resetPasswordForm">
        <input type="hidden" id="token" name="token" value="{{ token }}">
        
        <div class="form-group">
            <label for="password">{{ _('New password') }}</label>
            <input type="password" id="password" name="password" required>
        </div>
        <div id="password-rules" class="password-rules">
            <div id="length-rule" class="rule invalid">{{ _('At least 6 characters') }}</div>
            <div id="lower-rule" class="rule invalid">{{ _('One lowercase letter') }}</div>
            <div id="upper-rule" class="rule invalid">{{ _('One uppercase letter') }}</div>
            <div id="number-rule" class="rule invalid">{{ _('One digit') }}</div>
        </div>

        <div class="form-group">
            <label for="confirm_password">{{ _('Confirm the new password') }}</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        <button type="submit" class="button-primary">{{ _('Reset the password') }}</button>
    </form>
</div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/reset_password.js') }}"></script>
{% endblock %}

<< select_language.html >>:  
<!DOCTYPE html>
<html lang="{{ get_locale() }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ _('Welcome - Bienvenue') }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #e0f7fa 0%, #b2ebf2 100%);
            color: #004d40;
        }
        .selection-container {
            text-align: center;
            background: rgba(255, 255, 255, 0.8);
            padding: 3rem 4rem;
            border-radius: 15px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            backdrop-filter: blur(4px);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }
        .logo {
            width: 80px;
            margin-bottom: 1.5rem;
        }
        h1 {
            font-size: 1.8rem;
            margin-bottom: 2rem;
        }
        .language-buttons {
            display: flex;
            gap: 1.5rem;
            justify-content: center;
        }
        .lang-btn {
            background-color: #00796b;
            color: white;
            border: none;
            padding: 1rem 2.5rem;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.3s ease, transform 0.2s ease;
        }
        .lang-btn:hover {
            background-color: #004d40;
            transform: translateY(-3px);
        }
    </style>
</head>
<body>
    <div class="selection-container">
        <img src="{{ url_for('static', filename='images/logo.svg') }}" alt="{{ _('Business Logo') }}" class="logo">
        <h1>{{ _('Welcome / Bienvenue') }}</h1>
        <p>{{ _('Please select your language. / Veuillez sélectionner votre langue.') }}</p>
        <form method="POST" action="{{ url_for('select_language') }}">
            <div class="language-buttons">
                <button type="submit" name="language" value="en" class="lang-btn">English</button>
                <button type="submit" name="language" value="fr" class="lang-btn">Français</button>
            </div>
        </form>
    </div>
</body>
</html>

<< set_profile_photo.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Set Profile Photo') }} - Business{% endblock %}

{% block content %}
<div class="profile-photo-setup">
    <button id="ignore-btn" class="ignore-btn">{{ _('Ignore') }}</button>
    <div class="upload-container">
        <div class="upload-area" id="upload-area">
            <i class="fa-solid fa-cloud-arrow-up fa-3x"></i>
            <p>{{ _('Drag & drop or click to upload') }}</p>
            <input type="file" id="photo-input" accept="image/*" hidden>
            <button class="button-primary">{{ _('Choose Photo') }}</button>
        </div>
        <div id="preview-container" class="preview-container hidden">
            <img id="preview-img" src="" alt="Preview">
            <div class="preview-actions">
                <button id="upload-btn" class="button-primary">{{ _('Save') }}</button>
                <button id="cancel-btn" class="button-secondary">{{ _('Cancel') }}</button>
            </div>
        </div>
    </div>
</div>
<div id="message-container"></div>
{% endblock %}

{% block scripts %}
<script src="{{ url_for('static', filename='js/set_profile_photo.js') }}"></script>
{% endblock %}

<< settings.html >>:  
{% extends "base.html" %}

{% block title %}{{ _('Settings') }} - Troquez-Ici{% endblock %}

{% block content %}
<div class="settings-container">
    <h2>{{ _('Settings') }}</h2>
    <div id="settings-message-container"></div>

    <div class="settings-menu">
        <div class="settings-menu-item non-button">
            <i class="fa-solid fa-language fa-fw"></i>
            <div class="menu-item-text">
                <strong>{{ _('Language') }}</strong>
                <span>{{ _('Change the application language') }}</span>
            </div>
            <select id="language-switcher" class="language-switcher">
                <option value="fr" {% if get_locale() == 'fr' %}selected{% endif %}>Français</option>
                <option value="en" {% if get_locale() == 'en' %}selected{% endif %}>English</option>
            </select>
        </div>

        <button class="settings-menu-item" id="open-profile-modal">
            <i class="fa-solid fa-user-pen fa-fw"></i>
            <div class="menu-item-text">
                <strong>{{ _('Modify information') }}</strong>
                <span>{{ _('Username, email') }}</span>
            </div>
            <i class="fa-solid fa-chevron-right"></i>
        </button>

        <button class="settings-menu-item" id="open-password-modal">
            <i class="fa-solid fa-lock fa-fw"></i>
            <div class="menu-item-text">
                <strong>{{ _('Security and password') }}</strong>
                <span>{{ _('Change your password') }}</span>
            </div>
            <i class="fa-solid fa-chevron-right"></i>
        </button>

        <button class="settings-menu-item" id="logout-btn">
            <i class="fa-solid fa-right-from-bracket fa-fw"></i>
            <div class="menu-item-text">
                <strong>{{ _('Change account') }}</strong>
                <span>{{ _('Log out') }}</span>
            </div>
            <i class="fa-solid fa-chevron-right"></i>
        </button>

        <button class="settings-menu-item danger" id="open-delete-modal">
            <i class="fa-solid fa-trash-can fa-fw"></i>
            <div class="menu-item-text">
                <strong>{{ _('Delete account') }}</strong>
                <span>{{ _('This action is irreversible') }}</span>
            </div>
            <i class="fa-solid fa-chevron-right"></i>
        </button>
    </div>
</div>

<div id="profile-modal" class="modal-overlay hidden">
    <div class="modal-content">
        <button class="close-modal-btn">&times;</button>
        <h3>{{ _('Modify information') }}</h3>
        <form id="profile-form">
            <div class="form-group">
                <label for="username">{{ _('Username') }}</label>
                <input type="text" id="username" value="{{ g.user.username }}" required>
            </div>
            <div class="form-group">
                <label for="email">{{ _('Email address') }}</label>
                <input type="email" id="email" value="{{ g.user.email }}" required>
            </div>
            <div class="form-group">
    <label>{{ _('Profile Photo') }}</label>
    <div id="photo-upload-container" class="photo-upload">
        
        <div id="photo-preview-wrapper">
            {% if g.user.profile_photo %}
                <img id="current-photo" src="{{ url_for('uploaded_file', filename=g.user.profile_photo) }}" alt="Photo actuelle" class="current-photo-preview">
            {% else %}
                <div id="empty-avatar-placeholder" class="empty-avatar" style="cursor: pointer;">
                    <span>{{ g.user.username[0]|upper }}</span>
                    <i class="fa-solid fa-camera" style="color: rgba(255,255,255,0.8); font-size: 1.2rem; margin-top: 0.5rem;"></i>
                    <p style="font-size: 0.8rem; margin-top: 0.2rem;">{{ _('Ajouter une photo') }}</p>
                </div>
            {% endif %}
        </div>

        <div id="photo-buttons-wrapper" class="photo-buttons">
            {% if g.user.profile_photo %}
                <button type="button" id="edit-photo-btn" class="photo-btn primary">{{ _('Modifier') }}</button>
                <button type="button" id="delete-photo-btn" class="photo-btn danger">{{ _('Supprimer') }}</button>
            {% else %}
                <button type="button" id="add-photo-btn" class="photo-btn primary">{{ _('Ajouter une photo') }}</button>
            {% endif %}
        </div>
        
        <input type="file" id="photo-file" accept="image/*" hidden>
    </div>
</div>
    <button type="submit" class="button-primary">{{ _('Save') }}</button>
        </form>
    </div>
</div>

<div id="password-modal" class="modal-overlay hidden">
    <div class="modal-content">
        <button class="close-modal-btn">&times;</button>
        <h3>{{ _('Change the password') }}</h3>
        <form id="password-form">
            <div class="form-group">
                <label for="current-password">{{ _('Current password') }}</label>
                <input type="password" id="current-password" required>
            </div>
            <div class="form-group">
                <label for="new-password">{{ _('New password') }}</label>
                <input type="password" id="new-password" required>
            </div>
            <button type="submit" class="button-primary">{{ _('Update') }}</button>
        </form>
    </div>
</div>

<div id="delete-confirm-modal" class="modal-overlay hidden">
    <div class="modal-content">
        <button class="close-modal-btn">&times;</button>
        <h3>{{ _('Are you absolutely certain?') }}</h3>
        <p>{{ _('This action cannot be undone. Your account and all your data will be permanently deleted.') }}</p>
        <form id="delete-confirm-form">
            <div class="form-group">
                <label for="delete-password">{{ _('Confirm with your password') }}</label>
                <input type="password" id="delete-password" required>
            </div>
            <div class="modal-actions">
                <button type="button" class="button-secondary cancel-delete-btn">{{ _('Cancel') }}</button>
                <button type="submit" class="button-danger">{{ _('Permanently delete') }}</button>
            </div>
        </form>
    </div>
</div>

{% endblock %}


{% block scripts %}
<script src="{{ url_for('static', filename='js/settings.js') }}"></script>
{% endblock %}


===========
CSS COMPLET
===========

<< messages.css >>:
/* ===========================================================
   messages.css - Ultra-Modern 21st Century Messaging UI
   - Merged updates: Robust structure for perfect scroll, exact voice interface match, stylized quoted messages, improved mobile ergonomics
   - CORRECTIONS INTÉGRÉES : Layout mobile fixe, gestion de l'espace, positionnement du clavier emoji et de l'aperçu de réponse.
   =========================================================== */

/* ---------- 0. Base variables & fonts ---------- */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&display=swap');

:root {
  --bg: #f6f8fb;
  --surface: #ffffff;
  --muted: #9aa4b2;
  --text: #0f1723;
  --accent: #0066ff;
  --accent-2: #7c3aed; /* purple accent for gradients */
  --success: #12b886;
  --danger: #ff5252;
  --glass: rgba(255,255,255,0.6);
  --glass-2: rgba(255,255,255,0.04);
  --radius-lg: 18px;
  --radius-md: 12px;
  --radius-sm: 8px;
  --shadow-sm: 0 4px 12px rgba(16,24,40,0.06);
  --shadow-md: 0 10px 30px rgba(16,24,40,0.12);
  --transition-fast: 170ms;
  --transition-smooth: 300ms;
  --max-width: 1100px;
  --ui-gap: 14px;
  --message-width: min(74%, 680px);
  --incoming-bg: linear-gradient(135deg, #ffffff, #f3f6fb);
  --outgoing-bg: linear-gradient(135deg, #e6f0ff, #dbe9ff);
  --date-sep-bg: rgba(15,23,35,0.03);
  --elevate: 0 6px 22px rgba(2,6,23,0.08);
  --focus-ring: 0 0 0 4px rgba(0,102,255,0.08);
  --font: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
  --reply-bg: rgba(0, 0, 0, 0.05); 
  --reply-border: var(--accent);
  --header-height: auto; 
  --footer-base-height: none;
  --emoji-picker-height: 200px;
  --attachment-popup-height: 400px;
  
}

/* ---------- 1. Page layout ---------- */
.messages-page {
  font-family: var(--font);
  background: linear-gradient(180deg, var(--bg), var(--bg));
  color: var(--text);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.page-wrapper-chat {
  max-width: var(--max-width);
  margin: 1.5rem auto;
  padding: 1rem;
}

.chat-container {
  display: grid;
  grid-template-columns: 320px 1fr;
  gap: 1rem;
  align-items: stretch;
  overflow: hidden;
  /* MODIFICATION 1 : Donne une hauteur au conteneur sur ordinateur */
  height: calc(100vh - 3rem);
}

/* ======================================================================= */
/* --- CORRECTION : Layout mobile "WhatsApp" --- */
/* ======================================================================= */
@media (max-width: 767px) {
    /* Étape 1: Empêcher la page entière de scroller en mode chat */
    html, body {
        margin: 0;
        padding: 0;
        padding-bottom: 0;
    }
    html, body.in-chat-view {
        height: auto;
        overflow: hidden;
    }

    /* Étape 2: Forcer les conteneurs à occuper tout l'écran, sans marges */
    body.in-chat-view .page-wrapper-chat,
    body.in-chat-view .chat-container {
        height: 100vh;
        margin: 0;
        padding: 0;

    }
    
    .chat-container {
        grid-template-columns: 1fr;
        display: block;
        position: relative;
    }

    /* Logique de transition entre la liste et la discussion */
    .chat-list-panel, .chat-area-panel {
        /* Ces règles (position: absolute) écrasent les règles ordinateur */
        position: absolute; top: 0; bottom: 0; left: 0; width: 100%;
        height: 100%; /* S'assure que la hauteur est 100% sur mobile */
        transition: transform var(--transition-smooth);
        background: var(--bg);
        overflow: hidden; /* Empêche le panneau lui-même de scroller */
    }
    .chat-list-panel { transform: translateX(0); z-index: 10; }
    .chat-area-panel { transform: translateX(100%); z-index: 10; }
    .chat-container.chat-view-active .chat-list-panel { transform: translateX(-100%); }
    .chat-container.chat-view-active .chat-area-panel { transform: translateX(0); z-index: 3; }
    .chat-container.chat-view-active .chat-welcome-screen { display: none; }

  
    body.in-chat-view > header,
body.in-chat-view > footer {
    display: none !important;
}

    /* Étape 3: Structurer l'écran de discussion avec Flexbox */
    body.in-chat-view .chat-main-screen {
    display: flex;
    flex-direction: column;
    height: 100%; /* Doit maintenant hériter la pleine hauteur (top:0, bottom:0) */
    overflow: hidden;
    width: 100%;
    margin-top: 0;
}

    /* Étape 4: Fixer le header en haut */
    body.in-chat-view .chat-area-header {
        position: sticky;
        top: 0px;
        left: 0;
        width: 100%;
        height: var(--header-height);
        z-index: 101;
        border-radius: 0;
        box-shadow: var(--shadow-sm);
    }

    /* Étape 5: Faire de la zone de messages la seule partie scrollable */
    body.in-chat-view .messages-display {
        flex: 1; /* Prend tout l'espace disponible */
        overflow-y: auto; /* Active le scroll vertical */
        margin-bottom: 80px;
        /* Ajoute de l'espace pour ne pas être caché par le header et le footer */
        padding-top: var(--header-height);
        padding-bottom: 25px;
        padding-left: 0;
        padding-right: 0;
        transition: padding-bottom var(--transition-smooth); /* Pour l'animation emoji */
        background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23E0E7F1' fill-opacity='0.4'%3E%3Cpath d='M36 34.094c0 2.15-1.75 3.906-3.906 3.906H26.094A3.906 3.906 0 0 1 22.188 34.094V26.094A3.906 3.906 0 0 1 26.094 22.188h5.99c1.02 0 1.94.39 2.62.97l.01-1.05c0-2.15-1.75-3.906-3.906-3.906H26.094A3.906 3.906 0 0 0 22.188 22.094v12c0 2.15 1.75 3.906 3.906 3.906h5.812c2.15 0 3.906-1.75 3.906-3.906V34.094z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        background-color: #f0f2f5; /* Une couleur de fond douce */
    }

    /* Étape 6: Fixer la zone de saisie (footer) en bas */
    body.in-chat-view .message-input-area {
        position: fixed;
        bottom: 25px; /* Décalé pour laisser de la place au clavier emoji */
    
        left: 0;
        width: 100%;
        height: auto; 
        z-index: 10;
        margin: 0;
        border-radius: 0;
        background: var(--bg);
        flex-direction: column; 
        align-items: stretch;
        gap: 0;
        transition: bottom var(--transition-smooth); /* Pour l'animation emoji */
}
    
    /* --- CORRECTION CLÉ : Position de l'aperçu de réponse --- */
    #reply-preview-container {
        background: var(--surface);
        padding: 8px 12px;
        margin: 0;
        border-bottom: 1px solid rgba(0,0,0,0.05);
        border-left-width: 3px;
        border-radius: 0;
        order: -1; /* Place l'aperçu AVANT la zone de saisie dans le flex container */
    }
    #reply-preview-container.hidden { display: none; }

    /* --- CORRECTION CLÉ : Comportement du clavier Emoji --- */
    emoji-picker {
        display: none;
        position: fixed;
        bottom: calc(-1 * var(--emoji-picker-height)); /* Caché sous l'écran */
        left: 0;
        width: 100%;
        height: var(--emoji-picker-height);
        z-index: 1000;
        border-radius: 0;
        transition: bottom var(--transition-smooth);
    }
    emoji-picker.visible {
        display: block;
        bottom: 0; /* Apparaît en glissant depuis le bas */
    }

    /* Quand le picker est actif, on déplace TOUT le footer vers le haut */
    body.emoji-picker-active .message-input-area {
        bottom: var(--emoji-picker-height);
    }
    /* On ajuste aussi le padding des messages pour voir le dernier message */
    body.emoji-picker-active .messages-display {
        padding-bottom: calc(var(--footer-base-height) + var(--emoji-picker-height));
    }
    
    #message-input:focus { box-shadow: none; }
}

/* ---------- 2. Chat list (left column) ---------- */
.chat-list-panel {
  background: var(--surface);
  border-radius: var(--radius-lg);
  padding: 12px;
  box-shadow: var(--shadow-md);
  z-index: 3;
  height: 100%; /* <-- AJOUTÉ (pour remplir la grille) */
  overflow: hidden; /* <-- AJOUTÉ (pour que .chat-list-body scrolle) */
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--reply-bg);
}

.chat-list-header {
  padding: 6px 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 8px;
}

.chat-list-header h2 {
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--text);
}

.chat-list-body {
  padding: 6px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  flex: 1;
  overflow-y: auto; /* C'est cet élément qui doit scroller */
}

.chat-list-item {
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 10px;
  border-radius: 12px;
  cursor: pointer;
  transition: background var(--transition-fast), transform var(--transition-fast);
  user-select: none;
}

.chat-list-item:hover {
  background: rgba(2,6,23,0.02);
  transform: translateY(-2px);
}

.chat-list-item.active {
  background: linear-gradient(90deg, rgba(0,102,255,0.06), rgba(124,58,237,0.04));
  box-shadow: var(--elevate);
}

.chat-item-avatar, .avatar-img {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  flex-shrink: 0;
  display: grid;
  place-items: center;
  font-weight: 700;
  color: #fff;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  overflow: hidden;
  transition: box-shadow var(--transition-fast);
}

.chat-list-item:hover .chat-item-avatar {
  box-shadow: 0 0 12px rgba(0,102,255,0.3);
}

.avatar-img {
  object-fit: cover;
}

.chat-item-main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.chat-item-top-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}

.chat-item-time {
  font-size: 0.78rem;
  color: var(--muted);
  min-width: 44px;
  text-align: right;
}

.chat-item-bottom-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}

.last-message-preview {
  color: var(--muted);
  font-size: 0.9rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: flex;
  align-items: center;
  gap: 6px;
}

.notification-badge {
  background: linear-gradient(180deg, var(--danger), #c83636);
  color: #fff;
  font-size: 0.75rem;
  padding: 4px 7px;
  border-radius: 999px;
  font-weight: 700;
  box-shadow: 0 6px 18px rgba(200,40,40,0.12);
  animation: pulse 1.5s infinite;
}

@keyframes pulse {
  0% { transform: scale(1); }
  50% { transform: scale(1.05); }
  100% { transform: scale(1); }
}

.chat-status-icon {
  margin-right: 6px;
  font-size: 0.88rem;
  color: var(--muted);
}

/* ---------- 3. Chat area (right column) ---------- */
.chat-area-panel {
  background: transparent;
  display: flex;
  flex-direction: column;
  gap: 0;
  position: relative;
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-md); 
  height: 100%; /* <-- AJOUTÉ (pour remplir la grille) */
  overflow: hidden;
  z-index: 1;
}

.chat-welcome-screen {
  background: linear-gradient(180deg, var(--glass), var(--glass-2));
  border-radius: var(--radius-lg);
  padding: 40px;
  text-align: center;
  box-shadow: var(--shadow-sm);
  animation: fadeIn 0.5s ease-out;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}

.chat-welcome-screen .welcome-icon {
  font-size: 3rem;
  color: var(--accent);
  margin-bottom: 1rem;
  animation: bounceIn 1s ease-out;
}

@keyframes bounceIn {
  0% { transform: scale(0.8); opacity: 0; }
  60% { transform: scale(1.05); opacity: 1; }
  100% { transform: scale(1); }
}

.chat-main-screen {
  background: var(--surface);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-md);
  display: flex;
  flex-direction: column;
  height: 100%; /* <-- AJOUTÉ (pour remplir le panneau) */
  overflow: hidden;
  border: 1px solid rgba(15,23,35,0.03);
}

.chat-area-header {
  padding: 12px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid rgba(15,23,35,0.03);
  background: var(--glass);
  backdrop-filter: blur(10px);
  flex-shrink: 0;
  z-index: 10; /* S'assure qu'il est au-dessus de .messages-display */
}

.messages-display {
  flex: 1;
  padding: 16px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 8px;
  /* Fond pour ordinateur (la règle mobile l'écrasera) */
  background-color: var(--bg); 
}

.date-separator {
  text-align: center;
  margin: 12px 0;
  position: relative;
}

.date-separator span {
  background: var(--date-sep-bg);
  padding: 4px 12px;
  border-radius: 999px;
  font-size: 0.8rem;
  color: var(--muted);
  position: relative;
  z-index: 1;
}

.message-wrapper {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-width: var(--message-width);
  animation: messagePop 0.3s ease-out;
}

@keyframes messagePop {
  from { opacity: 0; transform: scale(0.95) translateY(10px); }
  to { opacity: 1; transform: scale(1) translateY(0); }
}

.message-wrapper.received {
  align-self: flex-start;
}

.message-wrapper.sent {
  align-self: flex-end;
  align-items: flex-end;
}

.message-bubble {
  padding: 10px 14px;
  border-radius: var(--radius-md);
  background: var(--incoming-bg);
  box-shadow: var(--shadow-sm);
  position: relative;
  backdrop-filter: blur(8px);
  transition: transform var(--transition-fast);
}

.message-wrapper.sent .message-bubble {
  background: var(--outgoing-bg);
}

.message-wrapper.received .message-bubble {
  border-top-left-radius: 0;
}

.message-wrapper.sent .message-bubble {
  border-top-right-radius: 0;
}
/* --- NOUVEAU : Style pour les messages sélectionnés --- */
.message-wrapper.selected > .message-bubble-container .message-bubble {
    background-color: rgba(5, 128, 250, 0.15); /* Surbrillance bleue semi-transparente */
    transform: scale(0.98); /* Léger effet de pression */
}

.message-bubble:hover {
  transform: translateY(-2px);
}

.message-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.78rem;
  color: var(--muted);
  opacity: 0.8;
}

.quoted-message {
  background: rgba(0, 0, 0, 0.05);
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  margin-bottom: 8px;
  border-left: 3px solid var(--accent);
  font-size: 0.9rem;
}

.quoted-message strong {
  color: var(--accent);
  display: block;
  margin-bottom: 4px;
}

/* --- Zone de saisie principale --- */
.message-input-area {
  padding: 8px 12px;
  background: var(--surface);
  border-top: 1px solid rgba(15,23,35,0.03);
  display: flex;
  align-items: flex-end;
  gap: 8px;
  position: relative;
  min-height: var(--footer-base-height);
  flex-shrink: 0; /* Empêche la zone de saisie de rétrécir */
}

.input-mode-text {
  display: flex;
  width: 100%;
  align-items: flex-end;
  gap: 8px;
}

.text-input-wrapper {
  flex-grow: 1;
  display: flex;
  align-items: center;
  background-color: var(--surface);
  border-radius: 24px;
  padding: 4px;
  box-shadow: var(--shadow-sm);
  border: 1px solid rgba(15,23,35,0.03);
}

#message-input {
  flex: 1;
  border: none;
  background: transparent;
  resize: none;
  max-height: 120px;
  overflow-y: auto;
  font-size: 1rem;
  color: var(--text);
  padding: 8px 4px;
}

#message-input::placeholder {
  color: var(--muted);
}

.chat-icon-button {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  background: transparent;
  border: none;
  cursor: pointer;
  display: grid;
  place-items: center;
  color: var(--muted);
  font-size: 1.2rem;
  flex-shrink: 0;
}

#mic-or-send-btn {
  background-color: var(--accent);
  color: white;
  box-shadow: var(--shadow-md);
  transition: transform 0.2s ease, background-color 0.2s ease;
}

#mic-or-send-btn:hover {
  transform: scale(1.1);
}

/* --- Popup d'attachements --- */
#attachment-popup {
  position: absolute;
  bottom: calc(100% + 10px);
  left: 12px;
  width: calc(100% - 24px);
  max-width: 350px;
  background: var(--surface);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-md);
  padding: 12px;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  opacity: 0;
  visibility: hidden;
  transform: translateY(10px);
  transition: all 0.2s ease-out;
  z-index: 1001;
}

#attachment-popup.active {
  opacity: 1;
  visibility: visible;
  transform: translateY(0);
}

.attachment-option {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 12px 8px;
  border-radius: var(--radius-md);
  cursor: pointer;
  background: none;
  border: none;
  color: var(--text);
  font-size: 0.8rem;
  transition: background-color 0.2s;
}

.attachment-option:hover {
  background-color: var(--glass-2);
}

.attachment-option i {
  font-size: 1.5rem;
  color: var(--accent);
}

/* --- Interface d'enregistrement vocal --- */
.input-mode-voice {
  display: none;
  width: 100%;
  flex-direction: column;
  justify-content: center;
  gap: 12px;
  height: 100%;
  align-items: center;
}

.message-input-area.recording-active .input-mode-text {
  display: none;
}

.message-input-area.recording-active .input-mode-voice {
  display: flex;
}

.voice-recorder-top {
  display: flex;
  align-items: center;
  gap: 16px;
  width: 100%;
}

#record-timer {
  font-family: monospace;
  font-size: 1rem;
  color: var(--muted);
  flex-shrink: 0;
}

#waveform-container {
  flex-grow: 1;
  height: 30px;
  display: flex;
  align-items: center;
  gap: 3px;
  overflow: hidden;
}

.waveform-bar {
  width: 3px;
  height: 5%;
  background-color: var(--muted);
  border-radius: 5px;
  transition: height 0.1s ease;
}

.message-input-area.recording-active .waveform-bar {
  background-color: var(--accent);
}

.voice-recorder-bottom {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  padding: 0 10px;
}

.voice-action-btn {
  background: none;
  border: none;
  cursor: pointer;
  color: var(--muted);
  font-size: 1.5rem;
  width: 50px;
  height: 50px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  transition: background-color 0.2s;
}

.voice-action-btn:hover {
  background-color: var(--glass-2);
}

#pause-resume-btn i {
  color: var(--danger);
}

#voice-send-btn {
  color: white;
  font-size: 1.2rem;
}

/* --- Couleurs personnalisées pour les boutons vocaux --- */
#cancel-voice-btn i {
  color: var(--danger);
}

#cancel-voice-btn:hover {
  background-color: rgba(255, 82, 82, 0.1);
}

#voice-send-btn {
  background-color: var(--accent);
  color: white;
}

#voice-send-btn:hover {
  filter: brightness(1.1);
}

#pause-resume-btn:hover {
  background-color: var(--glass-2);
}

/* --- Styles divers --- */
:focus {
  outline: none;
}

.chat-icon-button:focus, .chat-list-item:focus {
  box-shadow: var(--focus-ring);
}

@media (min-width: 768px) {
  .page-wrapper-chat {
    padding: 2rem;
  }
  .chat-list-panel {
    width: 320px;
  }
}

.upload-spinner {
    position: absolute;
    bottom: 5px;
    right: 5px;
    width: 16px;
    height: 16px;
    border: 2px solid rgba(0,0,0,0.2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
.message-wrapper.uploading .message-bubble {
   opacity: 0.7;
}
@keyframes spin {
    to { transform: rotate(360deg); }
}

.message-status.read i {
    color: #34b7f1; /* Un bleu vif, style WhatsApp/Telegram */
}

/* Empêche la sélection du texte à l'intérieur de la bulle lors d'un appui long */
.message-bubble {
  -webkit-user-select: none; /* Safari */
  -ms-user-select: none; /* IE 10+ */
  user-select: none; /* Standard */
}

/* Style pour une bulle de message sélectionnée */
.message-wrapper.selected > .message-bubble-container .message-bubble {
    background-image: none; /* On enlève le dégradé pour que la couleur soit uniforme */
    background-color: #d1e7ff; /* Un bleu clair de surbrillance */
    transform: scale(0.98); /* Léger effet de "pression" */
    transition: transform 150ms ease-out, background-color 150ms ease-out;
}

/* Style pour une bulle envoyée et sélectionnée */
.message-wrapper.sent.selected > .message-bubble-container .message-bubble {
    background-color: #c1d2ee; 
}

/* DANS : messages.css */
/* AJOUTEZ ce bloc (à la place de l'ancien) : */

/* --- Conteneur pour le bouton d'actions --- */
.chatroom-actions {
    display: flex;
    align-items: center;
    margin-left: 8px;
}

/* --- Style pour le bouton de suppression direct --- */
.chatroom-actions .delete-chatroom-btn {
    color: var(--muted);
    font-size: 1rem; /* Taille de l'icône */
    padding: 8px;
    border-radius: 50%;
    transition: background-color var(--transition-fast), color var(--transition-fast);
}

.chatroom-actions .delete-chatroom-btn:hover {
    color: var(--danger); /* Devient rouge */
    background-color: rgba(255, 82, 82, 0.08); /* Fond rouge léger */
}


<< profile.css >>:  
/* ============================================= */
/* --- STYLE DE LA PAGE PROFIL (MODERNISÉ) --- */
/* ============================================= */

:root {
    --star-color: #ffc107; /* Jaune doré pour les étoiles */
}

/* --- Conteneurs principaux --- */
.profile-container,
.profile-reviews-container {
    background-color: var(--light-surface-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-md);
    padding: 1.5rem;
    margin-bottom: 2rem;
}

/* --- En-tête du Profil (Avatar, Nom, etc.) --- */
.profile-header {
    display: flex;
    flex-direction: column; /* Empilé sur mobile */
    align-items: center;   /* Centré sur mobile */
    text-align: center;    /* Texte centré sur mobile */
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    border-bottom: 1px solid var(--border-color);
}

.profile-avatar {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    background-color: var(--primary-color);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 3rem;
    font-weight: 700;
    margin-bottom: 1rem; /* Marge en bas sur mobile */
    flex-shrink: 0;
}

.profile-info h1 {
    margin: 0 0 0.5rem 0;
    font-size: 1.8rem;
}

.profile-info p {
    margin: 0;
    color: var(--light-text-secondary);
}

.profile-email {
    font-size: 0.9rem;
    background-color: var(--light-bg-color);
    padding: 5px 10px;
    border-radius: var(--border-radius-sm);
    display: inline-block;
    margin-top: 10px;
    border: 1px solid var(--border-color);
}

.profile-info .button-primary {
    margin-top: 15px;
}

/* --- Note par étoiles --- */
.profile-rating {
    display: flex;
    flex-wrap: wrap; /* Permet de passer à la ligne si pas assez de place */
    justify-content: center; /* Centre sur mobile */
    align-items: center;
    gap: 0.5rem 1rem;
    margin-top: 10px;
}

.profile-rating .stars {
    font-size: 1.5rem;
}

.profile-rating .stars .star.filled {
    color: var(--star-color);
}

.profile-rating .stars .star {
    color: var(--border-color);
}

.profile-rating .rating-text {
    font-size: 0.9rem;
    color: var(--light-text-secondary);
}

/* --- Section des annonces de l'utilisateur --- */
.profile-content h2 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
}

/* --- Section des avis reçus --- */
.profile-reviews-container h3 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
}

.review-card {
    padding: 1.5rem 0;
    border-bottom: 1px solid var(--border-color);
}
.review-card:first-of-type {
    padding-top: 0;
}
.review-card:last-of-type {
    border-bottom: none;
    padding-bottom: 0;
}

.review-author {
    display: flex;
    align-items: center;
    margin-bottom: 1rem;
}

.author-avatar {
    width: 45px;
    height: 45px;
    border-radius: 50%;
    background-color: var(--light-text-secondary);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.2rem;
    font-weight: 600;
    margin-right: 1rem;
}

.author-info strong a {
    text-decoration: none;
    color: var(--light-text-color);
}
.author-info strong a:hover {
    color: var(--primary-color);
}

.review-date {
    font-size: 0.8rem;
    color: var(--light-text-secondary);
}

.review-stars {
    font-size: 1.2rem;
    margin-bottom: 0.75rem;
}

.review-stars .star.filled {
    color: var(--star-color);
}

.review-stars .star {
    color: var(--border-color);
}

.review-comment {
    color: var(--light-text-color);
    line-height: 1.6;
    background-color: var(--light-bg-color);
    padding: 1rem;
    border-radius: var(--border-radius-sm);
    border-left: 3px solid var(--primary-color);
    font-size: 0.9rem;
}

/* ============================================= */
/* --- Styles pour Ordinateur (min-width: 768px) --- */
/* ============================================= */
@media (min-width: 768px) {
    .profile-container,
    .profile-reviews-container {
        padding: 2.5rem;
    }

    .profile-header {
        flex-direction: row; /* Côte à côte sur grand écran */
        text-align: left;    /* Texte aligné à gauche */
    }

    .profile-avatar {
        margin-right: 2rem; /* Marge à droite sur grand écran */
        margin-bottom: 0;
    }

    .profile-rating {
        justify-content: flex-start; /* Aligné à gauche sur grand écran */
    }
}

<< style.css >>:  
/* ============================================= */
/* --- 1. VARIABLES & STYLES GLOBAUX --- */
/* ============================================= */

:root {
    --primary-color: #0d6efd;
    --primary-color-dark: #0b5ed7;
    --light-bg-color: #f8f9fa;
    --light-surface-color: #ffffff;
    --light-text-color: #212529;
    --light-text-secondary: #6c757d;
    --border-color: #dee2e6;
    --shadow-color: rgba(0, 0, 0, 0.075);
    --success-color: #198754;
    --error-color: #dc3545;
    --info-color: #6c757d;
    --font-family-base: 'Roboto', sans-serif;
    --border-radius-sm: 0.25rem;
    --border-radius-md: 0.5rem;
    --transition-speed: 0.2s;
     --service-color: #28a745;
/* Vert pour Services */
    --object-color: #17a2b8;
/* Bleu pour Objets */
    --gradient-service: linear-gradient(135deg, var(--service-color), #20c997);
    --gradient-object: linear-gradient(135deg, var(--object-color), #0dcaf0);
}

/* Force heure en noir en mode clair */
body:not(.dark-mode) .message-meta span,
body:not(.dark-mode) .chat-item-time {
    color: #000 !important;
}

body.dark-mode {
    --light-bg-color: #121212;
    --light-surface-color: #1e1e1e;
    --light-text-color: #e3e3e3;
    --light-text-secondary: #a0a0a0;
    --border-color: #343a40;
    --shadow-color: rgba(0, 0, 0, 0.25);
    --service-color: #198754; /* Vert plus sombre */
    --object-color: #0dcaf0;
/* Bleu plus clair en dark */
    --gradient-service: linear-gradient(135deg, #198754, #20c997);
    --gradient-object: linear-gradient(135deg, #0dcaf0, #17a2b8);
}

body.dark-mode .message-meta span,
body.dark-mode .chat-item-time {
    color: var(--light-text-secondary);
}

*, *::before, *::after {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: var(--font-family-base);
    background-color: var(--light-bg-color);
    color: var(--light-text-color);
    line-height: 1.6;
    transition: background-color var(--transition-speed) ease, color var(--transition-speed) ease;
}

a {
    color: var(--primary-color);
    text-decoration: none;
    transition: color var(--transition-speed) ease;
}
a:hover {
    color: var(--primary-color-dark);
    text-decoration: underline;
}

img {
    max-width: 100%;
    display: block;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1.5rem;
}

.hidden {
    display: none !important;
}

/* ============================================= */
/* --- 2. HEADER & NAVIGATION --- */
/* ============================================= */

header {
    background-color: var(--light-surface-color);
    box-shadow: 0 2px 4px var(--shadow-color);
    padding: 1rem 0;
    position: sticky;
    top: 0;
    z-index: 1000;
    transition: background-color var(--transition-speed) ease;
}

header nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo img {
    height: 35px;
    display: block;
}

.logo-container {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    text-decoration: none;
}

.logo-text {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--light-text-color);
}

.top-bar-left {
    display: flex;
    align-items: center;
    gap: 1.5rem;
}

.top-bar-right {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.center-desktop-nav {
    display: none;
}

.nav-item, .mobile-nav-item {
    position: relative;
}
.mobile-nav-item .nav-notification-badge {
    top: -5px !important;
    right: 10px !important;
    display: flex !important;
}

.nav-notification-badge {
    position: absolute;
    top: -8px; 
    right: -8px;
    background-color: var(--error-color);
    color: white;
    font-size: 0.7rem;
    font-weight: 700;
    min-width: 20px;
    height: 20px;
    border-radius: 10px;
    display: flex !important;
    align-items: center;
    justify-content: center;
    border: 2px solid var(--light-surface-color);
    padding: 0 4px;
    visibility: visible !important;
}

.center-desktop-nav .nav-notification-badge {
    top: -5px;
    right: 0px;
}

.nav-item.active, .mobile-nav-item.active {
    color: var(--primary-color) !important;
}

.nav-item.active i, .mobile-nav-item.active i {
    color: var(--primary-color) !important;
}

.nav-item:hover, .mobile-nav-item:hover {
    color: var(--primary-color-dark);
}

/* Mobile Nav */
.top-nav-level-2 {
    display: flex;
    justify-content: space-around;
    align-items: center;
    height: 55px;
    border-top: 1px solid var(--border-color);
}

.mobile-nav-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0;
    color: var(--light-text-secondary);
    font-size: 0.7rem;
    text-decoration: none;
}

.mobile-nav-item i {
    font-size: 1.8rem !important;
}

.mobile-nav-item span {
    display: none !important;
}

.mobile-nav-item.active i {
    color: var(--primary-color) !important;
}

.mobile-nav-item[href="/messages"] .nav-notification-badge {
    top: -15px; /* Ajusté pour être plus près du haut de l'icône */
    right: 15px;
/* Ajusté pour décaler le badge vers la gauche */
    background-color: red;
    color: white;
    border-radius: 50%;
    padding: 2px 6px;
    font-size: 0.7rem;
    font-weight: bold;
}

/* Search Bar */
.search-container {
    position: relative;
    display: flex;
    align-items: center;
}

.search-icon-btn {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1.2rem;
    color: var(--light-text-secondary);
    padding: 0.5rem;
}

.search-input-header-fake {
  /* Recopie les styles de ton ancien input : couleur, fond, padding, etc. */
  background-color: var(--input-bg);
  color: var(--text-color-secondary);
  padding: 0.5rem 1rem;
  border-radius: 20px;
  border: none;
  width: 100%;
  font-size: 0.9rem;
  cursor: pointer; /* Indique qu'on peut cliquer */
}

.search-container.active .search-input-header {
    width: 150px;
    opacity: 1;
    padding: 0.5rem;
    border-bottom: 2px solid var(--primary-color);
}

/* Theme Switch */
.theme-switch-wrapper {
    display: flex;
    align-items: center;
}

.theme-switch {
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    font-size: 1.3rem;
    color: var(--light-text-secondary);
    position: relative;
    width: 24px;
    height: 24px;
}

.theme-switch .sun-icon,
.theme-switch .moon-icon {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    transition: opacity 0.3s ease, transform 0.3s ease;
}

.theme-switch .sun-icon {
    opacity: 0;
    transform: translate(-50%, -50%) rotate(-90deg);
}

body.dark-mode .theme-switch .sun-icon {
    opacity: 1;
    transform: translate(-50%, -50%) rotate(0);
}

body.dark-mode .theme-switch .moon-icon {
    opacity: 0;
    transform: translate(-50%, -50%) rotate(90deg);
}

/* User Menu */
.user-menu { position: relative;
}

.user-menu-button {
    font-size: 1.1rem; /* Ajuste la taille de l'icône à l'intérieur */
    background-color: var(--light-bg-color);
/* Un fond léger */
    border: 1px solid var(--border-color);
/* Une bordure subtile */
    color: var(--light-text-secondary); /* Couleur de l'icône */
    width: 40px;
/* Largeur fixe */
    height: 40px; /* Hauteur fixe */
    border-radius: 50%;
/* La magie pour le rendre rond ! */
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.2s ease;
}

.user-menu-button:hover {
    background-color: var(--primary-color);
    color: white;
    border-color: var(--primary-color);
}

.user-menu-dropdown {
    display: none;
    position: absolute;
    top: 120%;
    right: 0;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    box-shadow: 0 5px 15px var(--shadow-color);
    border: 1px solid var(--border-color);
    list-style: none;
    padding: 0.5rem 0;
    width: 220px;
    z-index: 1100;
}

.user-menu-dropdown.active { display: block; }

.user-menu-dropdown li a {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
    color: var(--light-text-color);
    font-size: 0.9rem;
}

.user-menu-dropdown li a:hover {
    background-color: var(--light-bg-color);
    text-decoration: none;
}

.user-menu-dropdown i { width: 20px;
    text-align: center; }

li.separator { border-top: 1px solid var(--border-color); margin: 0.5rem 0;
}

/* Desktop Adjustments */
@media (min-width: 768px) {
    .top-nav-level-2 { display: none;
    }

    .top-nav-level-1 {
        gap: 2rem;
        justify-content: normal;
    }

    .center-desktop-nav {
        display: flex;
        gap: 2rem;
        margin: 0 auto;
    }

    .center-desktop-nav a {
        font-weight: 600;
        color: var(--light-text-secondary);
        text-decoration: none;
    }

    .center-desktop-nav a:hover {
        color: var(--primary-color);
    }

    .user-menu-button .mobile-icon { display: none; }
    .user-menu-button .desktop-icon { display: block;
    }

    .search-container.active .search-input-header { width: 200px; }
}

/* ============================================= */
/* --- 3. COMPOSANTS COMMUNS --- */
/* ============================================= */

.button-primary {
    background-color: var(--primary-color);
    color: #fff;
    border: none;
    padding: 0.75rem 1.5rem;
    font-family: var(--font-family-base);
    font-size: 1rem;
    font-weight: 600;
    border-radius: var(--border-radius-md);
    cursor: pointer;
    text-align: center;
    transition: background-color var(--transition-speed) ease, transform var(--transition-speed) ease;
}

.button-primary:hover, .button-primary:focus {
    background-color: var(--primary-color-dark);
    transform: translateY(-2px);
}

.button-primary:disabled {
    background-color: var(--light-text-secondary);
    cursor: not-allowed;
    transform: none;
}

.form-container {
    max-width: 500px;
    margin: 2rem auto;
    padding: 2.5rem;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    box-shadow: 0 4px 12px var(--shadow-color);
}

.form-container h2 { margin-bottom: 0.5rem;
    text-align: center; }

.form-container p { text-align: center; margin-bottom: 2rem; color: var(--light-text-secondary); }

.form-group { margin-bottom: 1.5rem; }

.form-group label { display: block;
    margin-bottom: 0.5rem; font-weight: 600; }

input[type="text"], input[type="email"], input[type="password"], input[type="search"], textarea, select {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-sm);
    background-color: var(--light-bg-color);
    color: var(--light-text-color);
    font-family: var(--font-family-base);
    font-size: 1rem;
    transition: border-color var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
}

input:focus, textarea:focus, select:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.25);
}

.form-footer-text { margin-top: 1.5rem; text-align: center; font-size: 0.9rem;
}

#message-container { margin: 1rem 0; }

.message { padding: 1rem; border-radius: var(--border-radius-sm); margin-bottom: 1rem; text-align: center; opacity: 1;
    transition: opacity 0.5s ease; }

.message.success { background-color: var(--success-color); color: white; }

.message.error { background-color: var(--error-color); color: white; }

.message.info { background-color: var(--info-color);
    color: white; }

.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
    opacity: 0;
    visibility: hidden;
    transition: opacity var(--transition-speed) ease, visibility var(--transition-speed) ease;
}

.modal-overlay:not(.hidden) { opacity: 1; visibility: visible; }

.modal-content { background-color: var(--light-surface-color); padding: 2rem;
    border-radius: var(--border-radius-md); box-shadow: 0 5px 15px rgba(0,0,0,0.3); width: 90%; max-width: 450px; position: relative; }

.close-modal-btn { position: absolute; top: 10px;
    right: 15px; background: none; border: none; font-size: 1.5rem; color: var(--light-text-secondary); cursor: pointer; }

.star-rating { display: flex; justify-content: center;
    margin: 1.5rem 0; }

.star-rating .star { font-size: 2.5rem; cursor: pointer; color: var(--border-color); transition: color 0.2s, transform 0.2s;
}

.star-rating:hover .star, .star-rating .star.hovered { color: #ffc107; transform: scale(1.1); }

.star-rating .star:hover ~ .star { color: var(--border-color); transform: scale(1);
}

/* ============================================= */
/* --- 4. STYLE DES ANNONCES --- */
/* ============================================= */

.hero-section { text-align: center; padding: 4rem 1rem; margin-bottom: 2rem;
    border-radius: var(--border-radius-md); background-color: var(--light-surface-color); }

.hero-section h1 { margin-bottom: 1rem; font-size: 2.5rem; }

.hero-section p { max-width: 600px;
    margin: 0 auto 1.5rem auto; color: var(--light-text-secondary); }

.posts-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; padding: 2rem 0;
}

.post-card { background-color: var(--light-surface-color); border-radius: var(--border-radius-md); overflow: hidden; box-shadow: 0 4px 8px var(--shadow-color); transition: transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
    position: relative; display: flex; flex-direction: column; }

.post-card:hover { transform: translateY(-5px); box-shadow: 0 8px 16px var(--shadow-color); }

.post-card-link { text-decoration: none;
    color: inherit; display: flex; flex-direction: column; flex-grow: 1; }

.post-card-link:hover { text-decoration: none; }

.post-card-image { height: 200px; background-size: cover; background-position: center;
}

.post-card-content { padding: 1.25rem; display: flex; flex-direction: column; flex-grow: 1; }

.post-card-category {
    font-size: 0.8rem;
    font-weight: 700;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
    padding: 0.25rem 0.6rem; /* Plus compact */
    border-radius: var(--border-radius-sm);
    display: inline-block;
/* Fond subtil avec transparence pour voir le texte */
    background: rgba(255, 255, 255, 0.8);
/* Blanc semi-transparent en light mode */
    color: var(--light-text-color);
/* Texte toujours visible */
    transition: all var(--transition-speed) ease;
    box-shadow: none;
/* On enlève l'ombre pour l'instant, on l'ajoute au hover */
}

/* Couleurs dynamiques par catégorie (dégradé léger) */
.category-service {
    background: linear-gradient(135deg, rgba(40, 167, 69, 0.15), rgba(32, 201, 151, 0.15));
/* Très transparent */
    color: var(--service-color); /* Texte en vert */
    border: 1px solid rgba(40, 167, 69, 0.3);
/* Bordure fine verte */
}

.category-objet {
    background: linear-gradient(135deg, rgba(23, 162, 184, 0.15), rgba(13, 202, 240, 0.15));
/* Très transparent */
    color: var(--object-color); /* Texte en bleu */
    border: 1px solid rgba(23, 162, 184, 0.3);
/* Bordure fine bleue */
}

/* En mode sombre : Ajuste pour contraste */
body.dark-mode .post-card-category {
    background: rgba(0, 0, 0, 0.3);
/* Gris sombre semi-transparent */
    color: var(--light-text-color);
}

body.dark-mode .category-service {
    background: linear-gradient(135deg, rgba(25, 135, 84, 0.2), rgba(32, 201, 151, 0.2));
    color: var(--service-color);
    border: 1px solid rgba(25, 135, 84, 0.4);
}

body.dark-mode .category-objet {
    background: linear-gradient(135deg, rgba(13, 202, 240, 0.2), rgba(23, 162, 184, 0.2));
    color: var(--object-color);
    border: 1px solid rgba(13, 202, 240, 0.4);
}

/* Hover pour un petit effet (optionnel, mais cool) */
.post-card:hover .post-card-category {
    transform: scale(1.05);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.post-card h3 { margin-bottom: 0.5rem; font-size: 1.2rem; line-height: 1.3;
}

.post-card p { color: var(--light-text-secondary); font-size: 0.9rem; flex-grow: 1; margin-bottom: 1rem; }

.post-card-footer { display: flex; justify-content: space-between; align-items: center;
    font-size: 0.8rem; color: var(--light-text-secondary); border-top: 1px solid var(--border-color); padding-top: 1rem; margin-top: auto; }

.favorite-btn { position: absolute; top: 10px; right: 10px;
    background: rgba(255, 255, 255, 0.8); border: none; border-radius: 50%; width: 40px; height: 40px; cursor: pointer; display: flex; align-items: center;
    justify-content: center; transition: transform 0.2s ease; }

.favorite-btn:hover { transform: scale(1.1); }

.favorite-btn svg { fill: var(--light-text-secondary); transition: fill 0.2s ease;
}

.favorite-btn.favorited svg { fill: var(--primary-color); }

.post-actions { display: flex; gap: 0.5rem; padding: 0.75rem; border-top: 1px solid var(--border-color);
}

.post-action-btn { flex-grow: 1; flex-basis: 0; justify-content: center; padding: 0.6rem 0.5rem; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.5rem;
    border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); background-color: var(--light-surface-color); color: var(--light-text-color); text-decoration: none; cursor: pointer;
    transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease; }

.post-action-btn:hover { background-color: var(--light-bg-color); border-color: var(--primary-color); }

.post-action-btn.edit { border-color: var(--info-color); color: var(--info-color);
}

.post-action-btn.edit:hover { background-color: rgba(108, 117, 125, 0.1); }

.post-action-btn.delete { border-color: var(--error-color); color: var(--error-color); }

.post-action-btn.delete:hover { background-color: rgba(220, 53, 69, 0.1);
}

/* ============================================= */
/* --- 5. PAGES SPÉCIFIQUES --- */
/* ============================================= */

.form-wrapper.hidden, .choice-box.hidden { display: none !important; }

.create-choice-container { display: flex;
    gap: 1.5rem; margin-bottom: 2rem; }

.choice-box { flex: 1; padding: 2rem 1rem; border: 2px solid var(--border-color); border-radius: var(--border-radius-md); text-align: center;
    cursor: pointer; transition: all var(--transition-speed) ease; }

.choice-box:hover { border-color: var(--primary-color); background-color: var(--light-bg-color); }

.choice-box.active { border-color: var(--primary-color);
    background-color: rgba(13, 110, 253, 0.1); box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.25);
}

.choice-box svg { margin: 0 auto 1rem auto; color: var(--primary-color); }

.choice-box span { display: block; }

.image-preview-container { display: grid;
    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 1rem; margin-bottom: 1rem; padding: 1rem; background-color: var(--light-bg-color); border-radius: var(--border-radius-md); }

.image-preview { position: relative; border-radius: var(--border-radius-sm);
    overflow: hidden; }

.image-preview img { width: 100%; height: 100%; object-fit: cover; }

.remove-image-btn { position: absolute; top: 5px; right: 5px;
    width: 24px; height: 24px; background-color: rgba(0, 0, 0, 0.6); color: white; border: none; border-radius: 50%; cursor: pointer; display: flex;
    align-items: center; justify-content: center; font-size: 1rem; font-weight: bold; line-height: 1; opacity: 0; transition: opacity 0.2s ease;
}

.image-preview:hover .remove-image-btn { opacity: 1; }

.post-detail-container { display: flex; flex-direction: column; gap: 2rem; padding: 2rem 0; }

.post-detail-image-container { width: 100%;
    position: relative; }

.photo-grid { display: grid; gap: 4px; border-radius: var(--border-radius-md); overflow: hidden; max-height: 500px; }

.photo-grid a { display: block;
    width: 100%; height: 100%; }

.photo-grid img { width: 100%; height: 100%; object-fit: cover; transition: transform 0.2s ease;
}

.photo-grid a:hover img { transform: scale(1.05); }

.photo-grid[data-count="1"] { grid-template-columns: 1fr; }

.photo-grid[data-count="2"] { grid-template-columns: 1fr 1fr; }

.photo-grid[data-count="3"] { grid-template-columns: 2fr 1fr;
    grid-template-rows: 1fr 1fr; }

.photo-grid[data-count="3"] a:first-child { grid-row: span 2; }

.photo-grid[data-count="4"] { grid-template-columns: 1fr 1fr; grid-template-rows: 1fr 1fr;
}

.photo-grid[data-count="5"] { grid-template-columns: 1fr 1fr; grid-template-rows: 1fr 1fr 1fr; }

.photo-grid[data-count="5"] a:first-child { grid-column: span 2;
}

/* ============================================= */
/* --- STYLE DE LA PAGE PROFIL --- */
/* ============================================= */

.profile-container,
.profile-reviews-container {
    background-color: var(--light-surface-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-md);
    padding: 1.5rem;
    margin-bottom: 2rem;
}

.profile-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    border-bottom: 1px solid var(--border-color);
}

.profile-avatar {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    background-color: var(--primary-color);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 3rem;
    font-weight: 700;
    margin-bottom: 1rem;
    flex-shrink: 0;
}

.profile-info h1 {
    margin: 0 0 0.5rem 0;
    font-size: 1.8rem;
}

.profile-info p {
    margin: 0;
    color: var(--light-text-secondary);
}

.profile-rating {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    align-items: center;
    gap: 0.5rem 1rem;
    margin-top: 10px;
}

.profile-rating .stars {
    font-size: 1.5rem;
}

.profile-rating .stars .star.filled {
    color: var(--star-color);
}

.profile-rating .stars .star {
    color: var(--border-color);
}

.profile-rating .rating-text {
    font-size: 0.9rem;
    color: var(--light-text-secondary);
}

.profile-email {
    font-size: 0.9rem;
    background-color: var(--light-bg-color);
    padding: 5px 10px;
    border-radius: var(--border-radius-sm);
    display: inline-block;
    margin-top: 10px;
    border: 1px solid var(--border-color);
}

.profile-info .button-primary {
    margin-top: 15px;
}

.profile-content h2 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
}

.profile-reviews-container h3 {
    font-size: 1.5rem;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
}

.review-card {
    padding: 1.5rem 0;
    border-bottom: 1px solid var(--border-color);
}

.review-card:first-of-type { padding-top: 0; }

.review-card:last-of-type { border-bottom: none;
    padding-bottom: 0; }

.review-author {
    display: flex;
    align-items: center;
    margin-bottom: 1rem;
}

.author-avatar {
    width: 45px;
    height: 45px;
    border-radius: 50%;
    background-color: var(--light-text-secondary);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.2rem;
    font-weight: 600;
    margin-right: 1rem;
}

.author-info strong a {
    text-decoration: none;
    color: var(--light-text-color);
}

.author-info strong a:hover { color: var(--primary-color);
}

.review-date {
    font-size: 0.8rem;
    color: var(--light-text-secondary);
}

.review-stars {
    font-size: 1.2rem;
    margin-bottom: 0.75rem;
}

.review-stars .star.filled { color: var(--star-color); }

.review-stars .star { color: var(--border-color); }

.review-comment {
    color: var(--light-text-color);
    line-height: 1.6;
    background-color: var(--light-bg-color);
    padding: 1rem;
    border-radius: var(--border-radius-sm);
    border-left: 3px solid var(--primary-color);
    font-size: 0.9rem;
}

/* Responsive Profil */
@media (min-width: 768px) {
    .profile-container,
    .profile-reviews-container { padding: 2.5rem;
    }

    .profile-header {
        flex-direction: row;
        text-align: left;
    }

    .profile-avatar { margin-right: 2rem; margin-bottom: 0; }

    .profile-rating { justify-content: flex-start;
    }
}

/* ============================================= */
/* --- 7. DARK MODE & RESPONSIVE GLOBAL --- */
/* ============================================= */

.theme-switch-wrapper { display: flex; align-items: center;
}

.theme-switch { position: relative; display: inline-block; width: 50px; height: 26px; }

.theme-switch input { opacity: 0; width: 0; height: 0;
}

.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px;
}

.slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%;
}

input:checked + .slider { background-color: var(--primary-color); }

input:checked + .slider:before { transform: translateX(24px);
}

@media (max-width: 768px) {
    .container { padding: 0 1rem;
    }

    main.container { padding: 1.5rem 1rem; }

    .form-container { padding: 1.5rem;
    }

    .hamburger { display: block; cursor: pointer; background: none; border: none; z-index: 1001;
    }

    .hamburger .line { width: 25px; height: 3px; background-color: var(--light-text-color); margin: 5px; transition: all 0.3s ease-in-out;
    }

    .hamburger.active .line:nth-child(1) { transform: rotate(45deg) translate(5px, 5px); }

    .hamburger.active .line:nth-child(2) { opacity: 0;
    }

    .hamburger.active .line:nth-child(3) { transform: rotate(-45deg) translate(7px, -6px);
    }

    .nav-links {
        position: fixed;
        top: 0;
        right: -100%;
        width: 80%;
        height: 100vh;
        background-color: var(--light-surface-color);
        box-shadow: -4px 0 10px var(--shadow-color);
        flex-direction: column;
        justify-content: center;
        gap: 2rem;
        transition: right 0.4s ease-in-out;
    }

    .nav-links.active { right: 0;
    }

    .nav-links a { font-size: 1.2rem; }

    .post-detail-container { grid-template-columns: 1fr;
    }
}

@media (min-width: 769px) {
    .hamburger.has-notification::after {
        content: '';
        position: absolute;
        top: 2px;
        right: 2px;
        width: 10px;
        height: 10px;
        background-color: var(--error-color);
        border-radius: 50%;
        border: 2px solid var(--light-surface-color);
    }
}

/* ============================================= */
/* --- 8. PAGE PARAMÈTRES --- */
/* ============================================= */

.settings-container h2 {
    margin-bottom: 2rem;
    text-align: center;
}

.settings-menu {
    max-width: 700px;
    margin: 0 auto;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    border: 1px solid var(--border-color);
    overflow: hidden;
}

.settings-menu-item {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 1rem 1.5rem;
    text-align: left;
    background: none;
    border: none;
    border-bottom: 1px solid var(--border-color);
    cursor: pointer;
    font-family: var(--font-family-base);
    color: var(--light-text-color);
    transition: background-color 0.2s ease;
}

.settings-menu-item:last-child { border-bottom: none;
}

.settings-menu-item:hover { background-color: var(--light-bg-color); }

.settings-menu-item i:first-child {
    font-size: 1.2rem;
    color: var(--light-text-secondary);
    width: 30px;
    margin-right: 1rem;
}

.menu-item-text {
    flex-grow: 1;
}

.menu-item-text strong {
    display: block;
    font-size: 1rem;
}

.menu-item-text span {
    font-size: 0.9rem;
    color: var(--light-text-secondary);
}

.settings-menu-item i.fa-chevron-right {
    font-size: 0.9rem;
    color: var(--light-text-secondary);
}

.settings-menu-item.danger .menu-item-text strong,
.settings-menu-item.danger i:first-child {
    color: var(--error-color);
}

.modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
    margin-top: 1.5rem;
}

.button-secondary {
    padding: 0.75rem 1.5rem;
    background-color: transparent;
    border: 1px solid var(--light-text-secondary);
    color: var(--light-text-secondary);
    border-radius: var(--border-radius-md);
    cursor: pointer;
}

.button-danger {
    padding: 0.75rem 1.5rem;
    background-color: var(--error-color);
    color: white;
    border: none;
    border-radius: var(--border-radius-md);
    cursor: pointer;
}

/* ============================================= */
/* --- 9. PAGES STATIQUES (AIDE) --- */
/* ============================================= */

.static-page-container {
    max-width: 800px;
    margin: 2rem auto;
    padding: 2.5rem;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    border: 1px solid var(--border-color);
}

.static-page-container h1 { text-align: center; margin-bottom: 0.5rem;
}

.static-page-container .subtitle { text-align: center; margin-bottom: 3rem; font-size: 1.1rem; color: var(--light-text-secondary); }

.help-section { margin-bottom: 3rem; padding-bottom: 2rem;
    border-bottom: 1px solid var(--border-color); }

.help-section:last-of-type { border-bottom: none; margin-bottom: 0; }

.help-section h2 { font-size: 1.8rem; margin-bottom: 1.5rem; color: var(--primary-color);
}

.help-section h3 { font-size: 1.3rem; margin-bottom: 1rem; }

.help-section p, .help-section ul { margin-bottom: 1rem; line-height: 1.7;
}

.help-section ul { list-style-position: inside; padding-left: 1rem; }

.toc { margin-bottom: 3rem; padding: 1.5rem; background-color: var(--light-bg-color); border-radius: var(--border-radius-sm);
}

.toc h3 { margin-bottom: 1rem; }

.toc ul { list-style: none; padding-left: 0; }

.toc ul li { margin-bottom: 0.5rem;
}

.toc ul li a { text-decoration: none; font-weight: 600; }

/* ============================================= */
/* --- 10. SÉLECTION MULTIPLE (MES ANNONCES) --- */
/* ============================================= */

.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.main-actions-menu { position: relative; }

.actions-button {
    background: none;
    border: none;
    padding: 0.5rem;
    cursor: pointer;
    font-size: 1.2rem;
    color: var(--light-text-secondary);
}

.actions-dropdown {
    display: none;
    position: absolute;
    top: 100%;
    right: 0;
    background-color: var(--light-surface-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-md);
    box-shadow: 0 4px 12px var(--shadow-color);
    min-width: 200px;
    z-index: 100;
    overflow: hidden;
    padding: 0.5rem 0;
}

.actions-dropdown.show { display: block; }

.actions-dropdown .dropdown-item,
.actions-dropdown a.dropdown-item {
    display: block;
    width: 100%;
    padding: 0.75rem 1rem;
    border: none;
    background: none;
    text-align: left;
    color: var(--light-text-color);
    cursor: pointer;
    font-size: 0.9rem;
    text-decoration: none;
}

.actions-dropdown .dropdown-item:hover,
.actions-dropdown a.dropdown-item:hover { background-color: var(--light-bg-color); }

.actions-dropdown .dropdown-item.danger { color: var(--error-color); }

.actions-dropdown hr { border: 0; border-top: 1px solid var(--border-color);
    margin: 0.5rem 0; }

.posts-grid.selection-mode .post-card-link { pointer-events: none; }

.post-card .selection-overlay {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(13, 110, 253, 0.5);
    display: flex;
    align-items: flex-start;
    justify-content: flex-start;
    padding: 10px;
    color: white;
    font-size: 1.5rem;
    opacity: 0;
    transition: opacity 0.2s ease;
    pointer-events: none;
    border-radius: var(--border-radius-md);
}

.post-card.selected { transform: scale(0.95);
}

.post-card.selected .selection-overlay { opacity: 1; }

.post-card { display: flex; flex-direction: column; justify-content: space-between; }

.post-actions { flex-wrap: wrap; padding: 0.5rem;
}

.post-action-btn { flex-grow: 1; text-align: center; }

/* Page Favoris */
.actions-menu { position: relative; }

.actions-dropdown { top: 100%; right: 0;
    margin-top: 0.5rem; }

/* Page Inscription */
.password-rules .rule { transition: color 0.3s ease; }

.password-rules .rule.invalid { color: var(--error-color);
}

.password-rules .rule.valid { color: var(--success-color); }

.password-rules .rule.valid::before { content: '? '; font-weight: bold; }

.password-rules .rule.invalid::before { content: '? ';
    font-weight: bold; }

/* Page Paramètres */
.settings-menu-item.non-button { display: flex; align-items: center; width: 100%; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border-color);
}

.language-switcher { margin-left: auto; padding: 0.5rem; border-radius: var(--border-radius-sm); border: 1px solid var(--border-color); background-color: var(--light-bg-color); color: var(--light-text-color);
}

/* Responsive Global */
@media (max-width: 768px) {
    .container { padding: 0 1rem;
    }
    main.container { padding: 1.5rem 1rem; }
    .form-container { padding: 1.5rem;
    }
}

@media (min-width: 769px) {
    .center-desktop-nav { display: flex;
    }
}
/* DANS static/css/style.css, ajoutez ceci dans la section "HEADER & NAVIGATION" */

.logo-text {
    font-size: 1.6rem;
/* Un peu plus grand pour compenser l'absence de logo */
    font-weight: 700;
    color: var(--primary-color);
/* La couleur bleue demandée */
    text-decoration: none;
}
.notification-bell {
    font-size: 1.3rem;
    color: var(--light-text-secondary);
    position: relative;
    padding: 0.5rem;
    display: flex;
    align-items: center;
}

.notification-bell .nav-notification-badge {
    top: -5px;
    right: -5px;
}
/* Dans style.css, ajoute pour notifications */

.notifications-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.notification-item {
    display: flex;
    align-items: center;
    padding: 1rem;
    background-color: var(--light-bg-color);
    border-radius: var(--border-radius-md);
    border: 1px solid var(--border-color);
    position: relative;
    cursor: pointer;
    transition: background-color 0.2s ease;
}

.notification-item:hover {
    background-color: var(--light-surface-color);
}

.notification-item.read {
    opacity: 0.7;
}

.notif-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background-color: var(--primary-color);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    margin-right: 1rem;
    flex-shrink: 0;
}

.notif-content {
    flex-grow: 1;
}

.notif-content p {
    margin: 0;
}

.notif-content strong {
    font-weight: 700;
}

.timestamp {
    font-size: 0.8rem;
    color: var(--light-text-secondary);
    display: block;
    margin-top: 0.25rem;
}

.notif-icon {
    position: absolute;
    bottom: 10px;
    right: 10px;
    font-size: 1rem;
    color: var(--star-color);
/* Jaune pour étoile ; pour bookmark, ajuste si besoin */
}

.notif-icon.fa-bookmark {
    color: var(--primary-color);
}
/* DANS static/css/style.css, à la fin du fichier */

/* === STYLES POUR LA SÉLECTION DES NOTIFICATIONS === */

/* Change le curseur quand on peut sélectionner */
/* DANS static/css/style.css, à la fin du fichier */

/* === STYLES (CORRIGÉS) POUR LA SÉLECTION DES NOTIFICATIONS === */

/* Change le curseur quand on peut sélectionner */
.notifications-list.selection-mode .notification-item {
    cursor: pointer;
}

/* Style appliqué à un item de notification quand il a la classe "selected" */
.notification-item.selected {
    background-color: rgba(13, 110, 253, 0.15);
/* Fond bleu très léger */
    border-left: 3px solid var(--primary-color);
/* Bordure gauche bleue pour bien marquer */
    border-color: var(--primary-color);
}
.post-card {
    /* ... styles existants ... */
    opacity: 0;
    transform: translateY(20px);
    animation: fadeInUp 0.5s ease forwards;
}

@keyframes fadeInUp {
    to {
        opacity: 1;
        transform: translateY(0);
    }
}
.loading-spinner {
    border: 4px solid var(--border-color);
    border-top: 4px solid var(--primary-color);
    border-radius: 50%;
    width: 20px;
    height: 20px;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg);
    }
    100% { transform: rotate(360deg); }
}
/* Animation fade-in pour les posts */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(30px); /* Monte de 30px */
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.post-card {
    animation: fadeInUp 0.6s ease-out forwards;
/* Applique à toutes les cartes */
    opacity: 0;
/* Cache au départ */
}

/* Délai progressif pour effet cascade (optionnel, cool pour les grids) */
.posts-grid .post-card:nth-child(1) { animation-delay: 0.1s;
}
.posts-grid .post-card:nth-child(2) { animation-delay: 0.2s; }
.posts-grid .post-card:nth-child(3) { animation-delay: 0.3s; }
.posts-grid .post-card:nth-child(n+4) { animation-delay: 0.4s;
} /* Les suivants à 0.4s */
/* Icônes thématiques pour catégories et avatars */
.category-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    margin-right: 0.5rem;
    color: var(--primary-color);
    transition: color var(--transition-speed) ease;
}

/* Icônes par catégorie (dans les badges) */
.category-service .category-icon {
    color: var(--service-color);
}

.category-objet .category-icon {
    color: var(--object-color);
}

/* Avatar avec icône (remplace l'initiale) */
.profile-avatar, .author-avatar, .notif-avatar {
    position: relative;
    overflow: hidden;
}

.profile-avatar::before, .author-avatar::before, .notif-avatar::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 24px;
    height: 24px;
    z-index: 1;
}

/* Exemples d'icônes (ajuste selon tes catégories) */
/* Pour "Service" : Icône d'outil */
[data-category="Service"] .profile-avatar::before,
.category-service + .profile-avatar::before { /* Si besoin de cibler plus finement */
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23ffffff'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1' /%3E%3C/svg%3E");
/* Wrench icon en blanc */
    background-size: contain;
}

/* Pour "Objet" : Icône de boîte */
[data-category="Objet"] .profile-avatar::before,
.category-objet + .profile-avatar::before {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23ffffff'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4' /%3E%3C/svg%3E");
/* Archive icon en blanc */
    background-size: contain;
}

/* Hover pour fun */
.post-card:hover .category-icon {
    transform: scale(1.1);
}
.category-icon {
    width: 18px;
    height: 18px;
    margin-right: 0.4rem;
    display: inline-block;
    vertical-align: middle;
    flex-shrink: 0;
    background-repeat: no-repeat;
    background-size: contain;
    background-position: center;
}

/* Service : Icône outil (wrench) */
.hi-wrench {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor' stroke-width='2'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' d='M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1' /%3E%3C/svg%3E");
}

/* Objet : Icône boîte (archive) */
.hi-archive {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor' stroke-width='2'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' d='M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4' /%3E%3C/svg%3E");
}

/* Couleurs par catégorie */
.category-service .category-icon { stroke: var(--service-color); } /* Vert pour le trait */
.category-objet .category-icon { stroke: var(--object-color);
} /* Bleu pour le trait */
/* Nav mobile : Icônes plus cool et interactives */
@media (max-width: 768px) {
    .mobile-nav-item i {
        font-size: 1.8rem !important;
/* Taille base mobile */
        color: var(--light-text-secondary);
        transition: all var(--transition-speed) ease;
        display: block;
        margin-bottom: 0.3rem; /* Plus d'espace sous icône (diminue rapprochement) */
    }

    /* Responsive : Plus petites sur très petits écrans */
    @media (max-width: 480px) {
        .mobile-nav-item i {
            font-size: 1.6rem !important;
/* Réduit sur mini-mobile */
            margin-bottom: 0.4rem;
/* Encore plus d'espace */
        }
    }

    .mobile-nav-item:hover i,
    .mobile-nav-item.active i {
        color: var(--primary-color);
        transform: scale(1.2);
        filter: drop-shadow(0 2px 4px rgba(13, 110, 253, 0.3));
    }

    .mobile-nav-item.create i {
        color: var(--success-color);
        font-size: 2rem !important;
/* Un peu plus grand pour "Create" (pop) */
    }

    .mobile-nav-item.create:hover i {
        transform: scale(1.3) rotate(90deg);
        color: #198754;
    }

    .mobile-nav-item span {
        font-size: 0.7rem;
        opacity: 0.8;
        padding-top: 0.2rem; /* Espace global pour aérer */
    }

    /* Aère la nav entière */
    .top-nav-level-2 {
        gap: 1rem;
/* Plus d'espace entre icônes */
        padding: 0.5rem;
/* Padding interne pour respirer */
    }
}
/* Footer posts : Auteur + Vues plus cool */
.post-card-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.85rem;
    color: var(--light-text-secondary);
    border-top: 1px solid var(--border-color);
    padding-top: 1rem;
    margin-top: auto;
    gap: 0.5rem;
/* Espace entre éléments */
}

.post-card-footer .author-info {
    display: flex;
    align-items: center;
    gap: 0.3rem;
/* Petit espace icône-nom */
    flex-grow: 1;
/* Prend l'espace dispo */
}

.post-card-footer .author-icon {
    width: 14px;
    height: 14px;
    color: var(--light-text-secondary);
    flex-shrink: 0;
}

.post-card-footer a {
    color: var(--light-text-secondary);
    text-decoration: none;
    font-weight: 600;
    transition: color var(--transition-speed) ease;
}

.post-card-footer a:hover {
    color: var(--primary-color); /* Bleu au hover */
    text-shadow: 0 0 4px rgba(13, 110, 253, 0.3);
/* Glow subtil */
}

.view-count {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    white-space: nowrap;
/* Garde ensemble */
}

.view-count svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
}

/* Responsive footer : Wrap sur très petit écran */
@media (max-width: 480px) {
    .post-card-footer {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
    }
}
.profile-photo-setup {
    max-width: 500px;
    margin: 2rem auto;
    text-align: center;
}
.ignore-btn {
    position: absolute;
    top: 1rem;
    left: 1rem;
    background: none;
    border: none;
    color: var(--light-text-secondary);
    font-size: 1rem;
    cursor: pointer;
}
.upload-container { padding: 2rem; }
.upload-area {
    border: 2px dashed var(--border-color);
    border-radius: var(--border-radius-md);
    padding: 3rem 2rem;
    transition: border-color var(--transition-speed);
    cursor: pointer;
}
.upload-area:hover { border-color: var(--primary-color); }
.upload-area i { color: var(--primary-color); margin-bottom: 1rem;
}
.upload-area p { color: var(--light-text-secondary); margin-bottom: 1rem; }
.preview-container { margin-top: 2rem; }
.preview-container img {
    width: 200px;
    height: 200px;
    border-radius: 50%;
    object-fit: cover;
    border: 3px solid var(--primary-color);
    margin-bottom: 1rem;
}
.preview-actions { display: flex; gap: 1rem; justify-content: center;
}
.photo-upload { text-align: center; margin-top: 1rem; }
.current-photo-preview {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid var(--border-color);
    margin-bottom: 0.5rem;
}
#photo-file { margin-bottom: 0.5rem; }
#delete-photo-btn { background: var(--error-color); color: white; border: none; padding: 0.5rem;
    border-radius: var(--border-radius-sm); cursor: pointer; }
.profile-avatar img.avatar-img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: inherit;
}
.author-initial {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--primary-color);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: bold;
}
.author-photo { width: 24px; height: 24px; border-radius: 50%; object-fit: cover;
}
.profile-photo-setup {
    position: relative; /* Container relatif pour absolute */
    max-width: 500px;
    margin: 2rem auto;
    text-align: center;
    padding-top: 2rem; /* Espace pour bouton */
}

.ignore-btn {
    position: absolute;
    top: 0;
    left: 0;
    background: var(--light-bg-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-sm);
    padding: 0.5rem 1rem;
    color: var(--light-text-secondary);
    font-size: 0.9rem;
    cursor: pointer;
    transition: background var(--transition-speed);
    z-index: 10; /* Au-dessus */
}

.ignore-btn:hover {
    background: var(--primary-color);
    color: white;
}
.empty-avatar {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    background: var(--primary-color);
    color: white;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border: 2px dashed rgba(255,255,255,0.5);
    transition: all var(--transition-speed);
}

.empty-avatar:hover {
    border-color: white;
    transform: scale(1.05);
    background: var(--primary-color-dark);
}

.photo-upload { position: relative; text-align: center; margin-top: 1rem; }
#delete-photo-btn { z-index: 2; }
.photo-upload { text-align: center; margin-top: 1rem;
}
.current-photo-preview {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid var(--border-color);
    margin-bottom: 0.5rem;
    display: block;
}

.photo-buttons {
    display: flex;
    gap: 0.5rem;
/* Espacement entre boutons */
    justify-content: center;
    margin-top: 0.5rem;
}

.photo-btn {
    padding: 0.4rem 0.8rem;
    border-radius: var(--border-radius-sm);
    border: none;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    transition: all var(--transition-speed);
    min-width: 80px;
/* Largeur min pour équilibre */
}

.photo-btn.primary {
    background: var(--primary-color);
    color: white;
}

.photo-btn.primary:hover {
    background: var(--primary-color-dark);
    transform: translateY(-1px);
}

.photo-btn.danger {
    background: var(--error-color);
    color: white;
}

.photo-btn.danger:hover {
    background: #dc3545;
    transform: translateY(-1px);
}

.empty-avatar:hover {
    transform: scale(1.05);
    background: var(--primary-color-dark);
}
/* Dans static/css/style.css */

/* === STYLES POUR L'UPLOAD DE PHOTO (PARAMÈTRES) === */

.photo-upload {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem; /* Espace entre l'aperçu et les boutons */
}

.current-photo-preview {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    object-fit: cover;
    border: 3px solid var(--primary-color);
    box-shadow: 0 4px 8px var(--shadow-color);
}

.empty-avatar {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    background: var(--primary-color);
    color: white;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border: 3px dashed rgba(255, 255, 255, 0.6);
    transition: all var(--transition-speed) ease;
}

.empty-avatar:hover {
    transform: scale(1.05);
    background: var(--primary-color-dark);
    border-color: white;
}

.photo-buttons {
    display: flex;
    gap: 0.75rem;
/* Espace entre les boutons */
    justify-content: center;
}

.photo-btn {
    padding: 0.5rem 1rem;
    border-radius: var(--border-radius-sm);
    border: none;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all var(--transition-speed) ease;
    min-width: 100px;
    text-align: center;
}

.photo-btn.primary {
    background-color: var(--primary-color);
    color: white;
}

.photo-btn.primary:hover {
    background-color: var(--primary-color-dark);
    transform: translateY(-2px);
    box-shadow: 0 4px 8px var(--shadow-color);
}

.photo-btn.danger {
    background-color: transparent;
    color: var(--error-color);
    border: 1px solid var(--error-color);
}

.photo-btn.danger:hover {
    background-color: var(--error-color);
    color: white;
    transform: translateY(-2px);
    box-shadow: 0 4px 8px var(--shadow-color);
}
/* Dans static/css/profile.css */

/* Style pour l'initiale dans l'avatar */
.profile-initial {
    font-size: 3.5rem;
/* Grande taille pour l'initiale */
    font-weight: 600;
    color: white;
}

/* Rendre la photo cliquable plus évidente au survol */
.profile-photo-clickable {
    cursor: pointer;
    transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
    width: 100%; /* S'assure que l'image remplit l'avatar */
    height: 100%;
    object-fit: cover;
    border-radius: 50%;
}

.profile-photo-clickable:hover {
    transform: scale(1.05);
    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
}


/* Styles pour la modale photo (réutilise le style de base) */
.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.8);
/* Fond plus sombre pour les images */
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.3s ease, visibility 0.3s ease;
}

.modal-overlay:not(.hidden) {
    opacity: 1;
    visibility: visible;
}

.modal-content-photo {
    position: relative;
    max-width: 90vw;
    max-height: 90vh;
}

#modal-image {
    display: block;
    max-width: 100%;
    max-height: 100%;
    border-radius: 8px; /* Bords arrondis pour l'image agrandie */
}

.close-modal-btn {
    position: absolute;
    top: -40px;
/* Positionne le bouton au-dessus de l'image */
    right: 0;
    background: none;
    border: none;
    font-size: 2.5rem;
    color: white;
    cursor: pointer;
    line-height: 1;
}
/* DANS static/css/style.css, AJOUTEZ CECI À LA FIN */

/* ============================================= */
/* --- 11. AMÉLIORATIONS MESSAGERIE & PROFIL --- */
/* ============================================= */

/* --- Nouveau Footer pour les cartes annonces --- */
.post-card-content h3 {
    min-height: 48px;
/* Assure une hauteur minimale pour 2 lignes */
}

.post-card-footer-new {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem 1rem;
    border-top: 1px solid var(--border-color);
    margin-top: auto;
    background-color: var(--light-surface-color);
/* AJOUTEZ CES DEUX LIGNES CI-DESSOUS */
    position: relative;
/* Nécessaire pour que z-index fonctionne */
    z-index: 2;
/* Force le pied de page à être au-dessus du lien principal */
}
.footer-left, .footer-center, .footer-right {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
    color: var(--light-text-secondary);
}
.author-photo-small {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    object-fit: cover;
}
.author-initial-small {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background-color: var(--primary-color);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 600;
}

/* --- Améliorations Profil --- */
.profile-stats {
    display: flex;
    gap: 1.5rem;
    margin-top: 1rem;
    flex-wrap: wrap;
    justify-content: center;
}
.profile-interest {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
    color: var(--light-text-secondary);
}
.profile-interest i {
    color: var(--primary-color);
    font-size: 1.2rem;
}

/* ============================================= */
/* --- 12. PRELOADER & UX EXTRAS --- */
/* ============================================= */

/* --- Preloader / Spinner --- */
#preloader {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 9999;
    background-color: var(--light-bg-color);
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 1;
    visibility: visible;
    transition: opacity 0.5s ease, visibility 0.5s ease;
}

#preloader.hidden {
    opacity: 0;
    visibility: hidden;
}

.spinner {
    width: 48px;
    height: 48px;
    border: 5px solid var(--border-color);
    border-bottom-color: var(--primary-color);
    border-radius: 50%;
    display: inline-block;
    box-sizing: border-box;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg);
    }
    100% { transform: rotate(360deg); }
}

/* --- Bouton "Retour en haut" --- */
#back-to-top {
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 45px;
    height: 45px;
    background-color: var(--primary-color);
    color: white;
    border: none;
    border-radius: 50%;
    font-size: 1.2rem;
    cursor: pointer;
    box-shadow: 0 4px 8px var(--shadow-color);
    opacity: 0;
    visibility: hidden;
    transform: translateY(20px);
    transition: all 0.3s ease;
    z-index: 1000;
}

#back-to-top.show {
    opacity: 1;
    visibility: visible;
    transform: translateY(0);
}

#back-to-top:hover {
    background-color: var(--primary-color-dark);
    transform: scale(1.1);
}

/* Sur mobile, on remonte le bouton pour ne pas gêner la barre de navigation */
@media (max-width: 768px) {
    #back-to-top {
        bottom: 80px;
/* Au-dessus de la nav mobile */
    }
}
/* DANS static/css/style.css, à la fin du fichier */

/* ============================================= */
/* --- 13. STYLES POUR MODALES INTERACTIVES --- */
/* ============================================= */

/* Base pour le fond de la modale */
.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.7);
/* Fond noir semi-transparent */
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.3s ease, visibility 0.3s ease;
    backdrop-filter: blur(5px); /* Effet de flou moderne */
}

.modal-overlay:not(.hidden) {
    opacity: 1;
    visibility: visible;
}

/* --- Modale pour l'image --- */
.modal-content-photo {
    position: relative;
    max-width: 90vw;
    max-height: 80vh;
    animation: zoomIn 0.3s ease-out;
}

#modal-image-content {
    display: block;
    max-width: 100%;
    max-height: 100%;
    border-radius: var(--border-radius-md);
    box-shadow: 0 10px 30px rgba(0,0,0,0.4);
}

/* --- Modale pour les alertes --- */
.alert-modal-content {
    background-color: var(--light-surface-color);
    padding: 2rem 2.5rem;
    border-radius: var(--border-radius-md);
    box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    width: 90%;
    max-width: 400px;
    text-align: center;
    animation: zoomIn 0.3s ease-out;
}

#alert-modal-text {
    font-size: 1.1rem;
    color: var(--light-text-color);
    margin-bottom: 2rem;
    line-height: 1.6;
}

.close-modal-btn-styled {
    min-width: 100px;
}

/* --- Bouton de fermeture générique --- */
.close-modal-btn {
    position: absolute;
    top: 15px;
    right: 20px;
    background: none;
    border: none;
    font-size: 2.5rem;
    color: white;
    cursor: pointer;
    line-height: 1;
    text-shadow: 0 1px 3px rgba(0,0,0,0.5);
}


/* Animation d'apparition */
@keyframes zoomIn {
    from {
        opacity: 0;
        transform: scale(0.9);
    }
    to {
        opacity: 1;
        transform: scale(1);
    }
}
/* ======================================================= */
/* --- 14. AMÉLIORATIONS VISUELLES DU FOOTER (CORRECTION) --- */
/* ======================================================= */

/* On supprime la rustine z-index qui n'est plus nécessaire */
.post-card-footer-new {
    z-index: initial;
/* Remplace z-index: 2; */
}

/* On agrandit le padding global du footer pour lui donner de l'air */
.post-card-footer-new {
    padding: 0.85rem 1.25rem;
/* Anciennement 0.75rem 1rem */
}

/* On augmente la taille de la photo de profil et de l'initiale */
.author-photo-small, .author-initial-small {
    width: 32px;
/* Anciennement 24px */
    height: 32px; /* Anciennement 24px */
}

/* On ajuste la taille de la police pour l'initiale */
.author-initial-small {
    font-size: 1rem;
/* Anciennement 0.8rem */
}

/* On augmente la taille de la police pour le nom et les compteurs */
.footer-left a, .footer-center span, .footer-right span {
    font-size: 0.95rem;
/* Un peu plus grand pour être lisible */
    font-weight: 500;
}

/* On grossit également les icônes pour qu'elles correspondent au texte */
.footer-center i, .footer-right i {
    font-size: 1.1rem;
/* Plus visible */
}
/* ============================================= */
/* --- 15. NOUVELLE NAVIGATION ADAPTATIVE --- */
/* ============================================= */

/* --- Styles de base pour les nouveaux éléments --- */
.icon-button {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1.3rem;
    color: var(--light-text-secondary);
    padding: 0.5rem;
    display: flex;
    align-items: center;
}

.language-menu {
    position: relative;
}

.language-menu-button {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1.3rem;
    color: var(--light-text-secondary);
    padding: 0.5rem;
}

.language-menu-dropdown {
    display: none;
    position: absolute;
    top: 120%;
    right: 0;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    box-shadow: 0 5px 15px var(--shadow-color);
    border: 1px solid var(--border-color);
    list-style: none;
    padding: 0.5rem 0;
    width: 150px;
    z-index: 1100;
}

.language-menu-dropdown.active {
    display: block;
}

.language-menu-dropdown li a {
    display: block;
    padding: 0.5rem 1rem;
    color: var(--light-text-color);
}

.language-menu-dropdown li a:hover {
    background-color: var(--light-bg-color);
    text-decoration: none;
}


/* --- Logique pour ECRANS MOBILES (par défaut) --- */

header {
    position: fixed;
/* Reste en haut */
    width: 100%;
    top: 0;
}

body {
    padding-top: 60px;
/* Espace pour le header fixe */
    padding-bottom: 60px;
/* Espace pour la nav du bas */
}

.top-nav-level-2 {
    display: flex;
/* Visible par défaut */
    justify-content: space-around;
    align-items: center;
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    height: 60px;
    background-color: var(--light-surface-color);
    border-top: 1px solid var(--border-color);
    box-shadow: 0 -2px 5px var(--shadow-color);
    z-index: 1000;
}

.nav-item-lvl2 {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.2rem;
    color: var(--light-text-secondary);
    font-size: 0.75rem;
    text-decoration: none;
    flex-grow: 1; /* Pour occuper tout l'espace */
    padding: 0.5rem 0;
}

.nav-item-lvl2 i {
    font-size: 1.5rem;
}

.nav-item-lvl2 span {
    display: block;
/* Toujours visible sur mobile */
}

/* Le bouton "+" est juste une icône */
.nav-item-lvl2.create i {
    font-size: 2.2rem;
}
.nav-item-lvl2.create span {
    display: none;
}

/* Masquer la nav centrale sur mobile */
.center-desktop-nav {
    display: none;
}


/* --- Logique pour GRANDS ECRANS (PC) --- */
@media (min-width: 769px) {
    header {
        position: sticky;
/* Comportement normal sur PC */
    }

    body {
        padding-top: 0;
/* Pas d'espace nécessaire */
        padding-bottom: 0;
    }

    /* La nav niveau 2 devient une barre sous la première */
    .top-nav-level-2 {
        position: relative;
/* N'est plus fixée en bas */
        height: auto;
        box-shadow: none;
        border-top: 1px solid var(--border-color);
        padding: 0.5rem 0;
        justify-content: center; /* Centrer les éléments */
        gap: 2.5rem;
/* Espace entre les éléments */
    }
    
    .nav-item-lvl2 {
        flex-direction: row;
/* Icône et texte côte à côte */
        gap: 0.5rem;
        font-size: 0.9rem;
        font-weight: 500;
        padding: 0.5rem 1rem;
        border-radius: var(--border-radius-sm);
        transition: background-color 0.2s ease;
    }

    .nav-item-lvl2:hover {
        background-color: var(--light-bg-color);
    }
    
    .nav-item-lvl2 i {
        font-size: 1.1rem;
    }

    .nav-item-lvl2.create {
        display: none;
/* Le bouton créer est déjà dans la barre principale sur PC */
    }

    /* Afficher la nav centrale sur PC */
    .center-desktop-nav {
        display: flex;
        margin: 0 auto;
        gap: 2rem;
    }
    
    /* Le bouton créer spécial pour PC */
    .center-desktop-nav a.create {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        background-color: var(--primary-color);
        color: white;
        padding: 0.5rem 1.2rem;
        border-radius: 50px;
        font-weight: 600;
    }
    .center-desktop-nav a.create:hover {
        background-color: var(--primary-color-dark);
        color: white;
        text-decoration: none;
    }
}
/* ======================================================= */
/* --- 15. NOUVELLE NAVIGATION PC & FILTRES MODERNES --- */
/* ======================================================= */

/* --- Style de la nouvelle navigation sur ordinateur --- */
@media (min-width: 768px) {
    .desktop-nav-item {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px; /* Espace entre l'icône et le texte */
        padding: 8px 12px;
        border-radius: var(--border-radius-md);
        color: var(--light-text-secondary);
        transition: all 0.2s ease-in-out;
        border: 2px solid transparent;
    }

    .desktop-nav-item:hover {
        color: var(--primary-color);
        background-color: var(--light-bg-color);
        text-decoration: none;
    }

    .desktop-nav-item.active {
        color: var(--primary-color);
        border-color: var(--primary-color);
        background-color: rgba(13, 110, 253, 0.05);
    }
    
    .desktop-nav-item i {
        font-size: 1.5rem;
    }
    
    .desktop-nav-item span {
        font-size: 0.8rem;
        font-weight: 600;
    }
}

/* --- Style du bouton "Créer une annonce" (PC & Mobile) --- */
.desktop-nav-item.nav-create-post,
.mobile-nav-item.create {
    color: var(--success-color);
}

.desktop-nav-item.nav-create-post:hover,
.mobile-nav-item.create:hover {
    color: white;
    background-color: var(--success-color);
}

.desktop-nav-item.nav-create-post.active,
.mobile-nav-item.create.active {
    color: white;
    background-color: var(--success-color);
    border-color: var(--success-color);
}


/* --- Style des nouveaux filtres sur la page Annonces --- */
.filters-and-nav-container {
    padding: 1rem;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    border: 1px solid var(--border-color);
    margin-bottom: 2rem;
}

.filters-bar-new {
    display: flex;
    flex-wrap: wrap;
/* Passe à la ligne sur mobile */
    gap: 1rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
    margin-bottom: 1rem;
}

.filter-group {
    display: flex;
    align-items: center;
    background-color: var(--light-bg-color);
    border-radius: var(--border-radius-sm);
    flex-grow: 1;
/* Les groupes prennent la même largeur */
}

.filter-group .filter-icon {
    padding: 0 0.75rem;
    color: var(--light-text-secondary);
}

.filter-group select {
    border: none;
    background: none;
    outline: none;
    box-shadow: none;
    width: 100%;
}

/* --- Style de la nouvelle sous-navigation par catégorie --- */
.category-nav {
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    flex-wrap: wrap;
}

.category-nav-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.6rem 1.2rem;
    border-radius: 50px;
/* Bords très arrondis */
    border: 1px solid var(--border-color);
    background-color: var(--light-surface-color);
    color: var(--light-text-color);
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 500;
    transition: all 0.2s ease-in-out;
}

.category-nav-item:hover {
    background-color: var(--light-bg-color);
    border-color: var(--primary-color);
    transform: translateY(-2px);
}

.category-nav-item.active {
    background-color: var(--primary-color);
    color: white;
    border-color: var(--primary-color);
    box-shadow: 0 4px 8px rgba(13, 110, 253, 0.2);
}

.category-nav-item.active i {
    color: white;
}

.category-nav-item i {
    color: var(--light-text-secondary);
    transition: color 0.2s ease;
}
/* ======================================================= */
/* --- 15. CORRECTIONS NAVIGATION & FILTRES MODERNES --- */
/* ======================================================= */

/* --- Correction de la navigation sur ordinateur --- */
@media (min-width: 769px) {
    /* On cache les classes 'mobile' et on affiche les classes 'desktop' */
    .mobile-nav-item {
        display: none;
    }
    .desktop-nav-item {
        display: flex;
/* Affiche les items sur PC */
        flex-direction: column;
        align-items: center;
        gap: 4px;
        padding: 8px 16px;
        border-radius: var(--border-radius-md);
        color: var(--light-text-secondary);
        transition: all 0.2s ease-in-out;
        border: 2px solid transparent;
        background: none;
    }
    
    .desktop-nav-item:hover {
        color: var(--primary-color);
        background-color: var(--light-bg-color);
        text-decoration: none;
    }

    .desktop-nav-item.active {
        color: var(--primary-color);
        border-color: var(--primary-color);
        background-color: rgba(13, 110, 253, 0.05);
    }
    
    .desktop-nav-item i {
        font-size: 1.5rem;
    }
    
    .desktop-nav-item span {
        font-size: 0.8rem;
        font-weight: 600;
        display: block !important; /* Force l'affichage du texte */
    }

    /* Le texte "Créer" est différent des autres */
    .desktop-nav-item .create-span {
        font-weight: 600;
    }
}


/* --- Style du bouton "Créer une annonce" (PC & Mobile) --- */
.nav-create-post,
.mobile-nav-item.create {
    color: var(--success-color) !important;
}

.nav-create-post:hover,
.mobile-nav-item.create:hover {
    color: white !important;
    background-color: var(--success-color);
}

.desktop-nav-item.nav-create-post.active,
.mobile-nav-item.create.active {
    color: white !important;
    background-color: var(--success-color);
    border-color: var(--success-color) !important;
}

/* On cache l'ancien `sub-nav` qui n'est plus utilisé */
.sub-nav {
    display: none;
}


/* --- Style des nouveaux filtres sur la page Annonces --- */
.filters-and-nav-container {
    padding: 1rem;
    background-color: var(--light-surface-color);
    border-radius: var(--border-radius-md);
    border: 1px solid var(--border-color);
    margin-bottom: 2rem;
}

.filters-bar-new {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
    margin-bottom: 1rem;
}

.filter-group {
    display: flex;
    align-items: center;
    background-color: var(--light-bg-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-sm);
    flex-grow: 1; 
}

.filter-group i {
    padding: 0 0.75rem;
    color: var(--light-text-secondary);
}

.filter-group select {
    border: none;
    background: none;
    outline: none;
    box-shadow: none;
    width: 100%;
}

.category-nav {
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    flex-wrap: wrap;
}

.category-nav-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.6rem 1.2rem;
    border-radius: 50px;
    border: 1px solid var(--border-color);
    background-color: var(--light-surface-color);
    color: var(--light-text-color);
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 500;
    transition: all 0.2s ease-in-out;
}

.category-nav-item:hover {
    background-color: var(--light-bg-color);
    border-color: var(--primary-color);
    transform: translateY(-2px);
}

.category-nav-item.active {
    background-color: var(--primary-color);
    color: white;
    border-color: var(--primary-color);
    box-shadow: 0 4px 8px rgba(13, 110, 253, 0.2);
}

.category-nav-item.active i {
    color: white;
}

.category-nav-item i {
    color: var(--primary-color);
    transition: color 0.2s ease;
}
/* ============================================= */
/* --- 16. MODERN SEARCH BAR (PAGE ANNONCES) --- */
/* ============================================= */

.modern-search-bar {
    position: relative;
    width: 100%;
    max-width: 400px; /* Limite la largeur sur les grands écrans */
}

.modern-search-bar .fa-search {
    position: absolute;
    top: 50%;
    left: 15px; /* Icône à l'intérieur, à gauche */
    transform: translateY(-50%);
    color: var(--light-text-secondary);
    font-size: 1rem;
}

.modern-search-bar input[type="search"] {
    width: 100%;
    padding: 0.8rem 1rem 0.8rem 45px;
/* Espace à gauche pour l'icône */
    border-radius: 50px;
/* Bords très arrondis */
    border: 1px solid var(--border-color);
    background-color: var(--light-surface-color);
    font-size: 1rem;
    transition: all 0.2s ease-in-out;
}

.modern-search-bar input[type="search"]:focus {
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.25);
}

.modern-search-bar input[type="search"]::placeholder {
    color: var(--light-text-secondary);
}

/* On s'assure que le header s'adapte bien */
@media (max-width: 600px) {
    .page-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 1rem;
    }
    .modern-search-bar {
        max-width: 100%;
    }
}
/* ======================================================= */
/* --- 17. MODERNISATION RECHERCHE PAGE D'ACCUEIL --- */
/* ======================================================= */

/* Style spécifique pour la barre de recherche sur la page d'accueil */
.homepage-search {
    max-width: 600px;
/* Plus large que sur la page des annonces */
    margin: 2rem auto 0 auto;
/* Centrée et avec de l'espace au-dessus */
}

.homepage-search input[type="search"] {
    padding: 1rem 1rem 1rem 55px;
/* Plus haute pour un meilleur impact */
    font-size: 1.1rem;
    background-color: var(--light-surface-color);
/* Fond blanc pour contraster */
}

.homepage-search .fa-search {
    font-size: 1.2rem;
    left: 20px;
/* Un peu plus d'espace pour l'icône */
}
/* ============================================= */
/* --- 18. ANIMATIONS D'APPARITION AU SCROLL --- */
/* ============================================= */

/*
  État initial de nos cartes d'annonces :
  - Complètement transparentes (opacity: 0)
  - Légèrement décalées vers le bas (transform: translateY(20px))
*/
.post-card {
    opacity: 0;
    transform: translateY(20px);
    transition: opacity 0.6s ease-out, transform 0.6s ease-out;
}

.post-card.visible {
    opacity: 1;
    transform: translateY(0);
}
/* ======================================================= */
/* --- 19. MODERNISATION RECHERCHE HEADER & FORMULAIRES --- */
/* ======================================================= */

/* --- Barre de recherche du header --- */
.top-nav-level-1 .search-container {
    background-color: var(--light-bg-color);
    border-radius: 50px;
    transition: all 0.3s ease;
    border: 1px solid transparent;
}

.top-nav-level-1 .search-container:focus-within {
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.2);
}

.top-nav-level-1 .search-input-header {
    width: 0;
/* Caché par défaut */
    border: none;
    background: transparent;
    padding: 0;
    transition: all 0.3s ease;
}

.top-nav-level-1 .search-icon-btn {
    color: var(--light-text-secondary);
}

/* Quand on clique sur l'icône sur mobile */
.top-nav-level-1 .search-container.active .search-input-header {
    width: 150px;
    padding: 0.5rem 0 0.5rem 1rem;
}

/* Sur PC, la barre est toujours un peu visible */
@media(min-width: 769px) {
    .top-nav-level-1 .search-input-header {
        width: 200px;
        padding: 0.5rem 0 0.5rem 1rem;
    }
}
/* --- Style global pour les formulaires --- */
/* --- Style pour la prévisualisation des images --- */
.image-preview-container {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-top: 1rem;
}
.image-preview {
    position: relative;
    width: 100px;
    height: 100px;
}
.image-preview img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: var(--border-radius-sm);
    border: 1px solid var(--border-color);
}
.remove-image-btn {
    position: absolute;
    top: -5px;
    right: -5px;
    width: 22px;
    height: 22px;
    background-color: var(--error-color);
    color: white;
    border: none;
    border-radius: 50%;
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: bold;
    display: flex;
    align-items: center;
    justify-content: center;
}
.form-container {
    padding: 2rem;
}

.form-group {
    margin-bottom: 1.5rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
    color: var(--light-text-secondary);
}

.form-group input,
.form-group textarea,
.form-group select {
    width: 100%;
    padding: 0.8rem 1rem;
    font-size: 1rem;
    background-color: var(--light-bg-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-md); /* Bords arrondis */
    color: var(--light-text-color);
    transition: all 0.2s ease-in-out;
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
    outline: none;
    border-color: var(--primary-color);
    background-color: var(--light-surface-color);
    box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.2);
}
/* --- Correction pour la superposition de la nav mobile --- */
@media (max-width: 768px) {
    main.container + footer {
        margin-bottom: 60px;
/* Hauteur de la barre de navigation */
    }
}
/* ======================================================= */
/* --- 20. SYSTÈME DE GÉOLOCALISATION --- */
/* ======================================================= */

/* Style pour la localisation sur les cartes d'annonces */
.post-card-location {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
    color: var(--light-text-secondary);
    margin-top: 0.75rem;
/* Espace sous le titre */
    font-weight: 500;
}

.post-card-location i {
    color: var(--primary-color);
    font-size: 0.9rem;
}

/* Style pour la localisation sur la page de détail */
.post-detail-meta {
    display: flex;
    flex-direction: column; /* Empile les infos */
    gap: 0.5rem;
/* Espace entre les lignes */
    margin-bottom: 1.5rem;
    color: var(--light-text-secondary);
}

.post-detail-location {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 1rem;
}

.post-detail-location i {
    color: var(--primary-color);
    font-size: 1.1rem;
}

/* Amélioration de Choices.js pour la sélection multiple */
.choices__list--multiple .choices__item {
    background-color: var(--primary-color);
    border: 1px solid var(--primary-color-dark);
    color: white;
    font-weight: 500;
}

.choices__list--multiple .choices__item .choices__button {
    border-left: 1px solid rgba(0, 0, 0, 0.2);
    filter: invert(1);
/* Rend la croix de suppression blanche */
}
/* Style pour la zone de téléversement d'images modernisée */
.upload-area {
    border: 2px dashed var(--border-color);
    border-radius: var(--border-radius-md);
    padding: 2rem;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s ease-in-out;
    background-color: var(--light-bg-color);
    margin-top: 0.5rem;
}

.upload-area:hover {
    border-color: var(--primary-color);
    background-color: var(--light-surface-color);
}

.upload-area i {
    color: var(--primary-color);
    margin-bottom: 1rem;
}

.upload-area p {
    color: var(--light-text-secondary);
    margin: 0;
}
.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    gap: 1rem;
    flex-wrap: wrap; /* Permet de passer à la ligne sur petits écrans */
}

/* --- Formulaire de création d'annonce moderne --- */
.modern-form .subtitle {
    font-size: 1.1rem;
    margin-bottom: 2.5rem;
}
.form-step {
    border: none;
    padding: 0;
    margin: 0 0 2.5rem 0;
}
.form-step legend {
    font-size: 1.2rem;
    font-weight: 600;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    color: var(--primary-color);
}
.step-number {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    background-color: var(--primary-color);
    color: white;
    font-size: 1rem;
}
.form-group-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
}
.choice-pills {
    display: flex;
    gap: 0.75rem;
}
.pill-btn {
    flex: 1;
    padding: 0.8rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: 50px;
    background-color: var(--light-surface-color);
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-weight: 500;
}
.pill-btn:hover {
    background-color: var(--light-bg-color);
    border-color: var(--primary-color);
}
.pill-btn.active {
    background-color: var(--primary-color);
    color: white;
    border-color: var(--primary-color);
}
.cover-badge {
    position: absolute;
    top: 5px;
    left: 5px;
    background-color: rgba(0, 0, 0, 0.6);
    color: white;
    font-size: 0.7rem;
    padding: 2px 6px;
    border-radius: var(--border-radius-sm);
}
.submit-btn-large {
    width: 100%;
    padding: 1rem;
    font-size: 1.1rem;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
}
.spinner-small {
    width: 20px;
    height: 20px;
    border: 3px solid rgba(255,255,255,0.3);
    border-bottom-color: white;
    border-radius: 50%;
    display: inline-block;
    animation: spin 1s linear infinite;
}

/* ======================================================= */
/* --- 22. MODERNISATION FORMULAIRE DE CRÉATION --- */
/* ======================================================= */

@media (max-width: 600px) {
    /* On passe les 2 colonnes en 1 seule sur mobile */
    .form-group-grid {
        grid-template-columns: 1fr;
        gap: 1.5rem; /* On garde un espace vertical */
    }

    /* On s'assure que les boutons pilules ne débordent pas */
    .choice-pills {
        flex-wrap: wrap;
/* Permet de passer à la ligne si besoin */
    }

    .pill-btn {
        flex-grow: 1;
/* Permet aux boutons de prendre la largeur disponible */
    }
}

footer {
    text-align: center;
    padding: 2rem 0;
    color: var(--light-text-secondary);
    font-size: 0.9rem;
    border-top: 1px solid var(--border-color);
    background-color: var(--light-surface-color);
}
/* DANS static/css/style.css */

/* --- Amélioration des actions dans la modale --- */

/* On transforme le conteneur en flexbox pour aligner les boutons */
.modal-actions {
    display: flex;
    justify-content: flex-end; /* Aligne les boutons à droite */
    gap: 0.75rem; /* Espace entre les boutons */
    margin-top: 2rem; /* Espace au-dessus des boutons */
}

/* Style pour un bouton secondaire (notre bouton "OK") */
.button-secondary {
    padding: 0.65rem 1.5rem;
    background-color: transparent;
    border: 1px solid var(--border-color);
    color: var(--light-text-secondary);
    border-radius: var(--border-radius-md);
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
}

.button-secondary:hover {
    background-color: var(--light-bg-color);
    border-color: var(--light-text-secondary);
}
/* DANS static/css/style.css */

/* Centre les actions de la modale si elle n'a qu'un seul bouton */
.modal-actions.center-actions {
    justify-content: center;
}

/* Ajoute un petit espace entre l'icône et le texte du bouton */
.button-primary i {
    margin-right: 0.5rem;
}
.post-card.selected {
    transform: scale(0.97); /* Effet de rétrécissement pour montrer la sélection */
    box-shadow: 0 0 0 3px var(--primary-color), 0 8px 16px var(--shadow-color); /* Bordure bleue et ombre plus prononcée */
    border-color: var(--primary-color);
}

/* On s'assure que la transition est fluide */
.post-card {
    transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
}


/* --- Style pour une notification sélectionnée --- */
.notification-item.selected {
    background-color: rgba(13, 110, 253, 0.1); /* Fond bleu très léger */
    border-left: 4px solid var(--primary-color); /* Bordure gauche bleue bien visible */
    border-color: var(--primary-color);
}

/* ============================================= */
/* --- 23. ANIMATIONS ET AMÉLIORATIONS UX --- */
/* ============================================= */

/* --- Animation d'apparition au scroll --- */



/* --- Preloader amélioré --- */
.spinner {
    width: 48px;
    height: 48px;
    border: 5px solid var(--border-color);
    border-bottom-color: var(--primary-color); /* Fait tourner juste une partie */
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

/* --- Style pour les conversations par annonce --- */
.chat-item-post-title {
    font-size: 0.8rem;
    color: var(--light-text-secondary);
    font-style: italic;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* --- Menu d'actions sur les conversations --- */
.chatroom-actions {
    margin-left: auto;
}
.more-actions-btn {
    color: var(--light-text-secondary);
}

/* --- Vidéos dans le chat --- */
.chat-video {
    max-width: 100%;
    border-radius: var(--border-radius-sm);
    display: block;
}

/* --- Header de sélection de message --- */
.selection-actions {
    display: flex;
    gap: 1rem;
    margin-left: auto;
}

/* --- Spinner de chargement des messages --- */
.spinner-container {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100%;
}


===========================
TRADUCTION COMPLETE DU SITE
===========================
<< messages.po >>:  
msgid ""
msgstr ""
"Project-Id-Version: Business 1.0\n"
"Report-Msgid-Bugs-To: \n"
"POT-Creation-Date: 2025-10-01 00:00+0000\n"
"PO-Revision-Date: 2025-10-01 00:00+0000\n"
"Last-Translator: AI Assistant\n"
"Language-Team: xAI\n"
"Language: fr\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Content-Transfer-Encoding: 8bit\n"
"Plural-Forms: nplurals=2; plural=(n > 1);\n"

msgid "Home"
msgstr "Accueil"

msgid "Posts"
msgstr "Annonces"

msgid "Messages"
msgstr "Messages"

msgid "My Posts"
msgstr "Mes annonces"

msgid "My Favorites"
msgstr "Mes favoris"

msgid "Profile"
msgstr "Profil"

msgid "Settings"
msgstr "Paramètres"

msgid "Help"
msgstr "Aide"

msgid "Notifications"
msgstr "Notifications"

msgid "Logout"
msgstr "Déconnexion"

msgid "Login"
msgstr "Connexion"

msgid "Register"
msgstr "Inscription"

msgid "Search..."
msgstr "Rechercher..."

msgid "Change theme"
msgstr "Changer le thème"

msgid "Search"
msgstr "Rechercher"

msgid "Create Post"
msgstr "Créer une annonce"

msgid "All rights reserved."
msgstr "Tous droits réservés."

msgid "Go to top"
msgstr "Aller en haut"

msgid "Exchanges, Share, Discover."
msgstr "Échanges, Partage, Découverte."

msgid "Give a second life to your objects and share your services with a benevolent local community."
msgstr "Donnez une seconde vie à vos objets et partagez vos services avec une communauté bienveillante locale."

msgid "See all ads"
msgstr "Voir toutes les annonces"

msgid "Last Ads"
msgstr "Dernières annonces"

msgid "No ad for the moment. Be the first to create one!"
msgstr "Aucune annonce pour le moment. Soyez le premier à en créer une !"

msgid "Save"
msgstr "Sauvegarder"

msgid "Object"
msgstr "Objet"

msgid "Service"
msgstr "Service"

msgid "person(s) interact with this ad."
msgstr "%(count)s personne(s) interagissent avec cette annonce."

msgid "This ad has been viewed %(count)s times."
msgstr "Cette annonce a été consultée %(count)s fois."

msgid "Log in"
msgstr "Se connecter"

msgid "Happy to see you again!"
msgstr "Ravi de vous revoir !"

msgid "Email address"
msgstr "Adresse e-mail"

msgid "Password"
msgstr "Mot de passe"

msgid "Forgot password?"
msgstr "Mot de passe oublié ?"

msgid "Not an account yet? Sign up here."
msgstr "Pas encore de compte ? Inscrivez-vous ici."

msgid "Your account has been successfully confirmed! You can now log in."
msgstr "Votre compte a été confirmé avec succès ! Vous pouvez maintenant vous connecter."

msgid "Your account has already been confirmed. You can log in."
msgstr "Votre compte a déjà été confirmé. Vous pouvez vous connecter."

msgid "Your password has been successfully reset."
msgstr "Votre mot de passe a été réinitialisé avec succès."

msgid "Create an account"
msgstr "Créer un compte"

msgid "Join our exchange and sharing community."
msgstr "Rejoignez notre communauté d'échanges et de partages."

msgid "Username"
msgstr "Nom d'utilisateur"

msgid "Confirm the password"
msgstr "Confirmer le mot de passe"

msgid "Sign up"
msgstr "S'inscrire"

msgid "Already have an account? Log in here."
msgstr "Déjà un compte ? Connectez-vous ici."

msgid "At least 6 characters"
msgstr "Au moins 6 caractères"

msgid "One lowercase letter"
msgstr "Une lettre minuscule"

msgid "One uppercase letter"
msgstr "Une lettre majuscule"

msgid "One digit"
msgstr "Un chiffre"

msgid "The password does not meet all the rules."
msgstr "Le mot de passe ne respecte pas toutes les règles."

msgid "The passwords do not match."
msgstr "Les mots de passe ne correspondent pas."

msgid "Forgot password"
msgstr "Mot de passe oublié"

msgid "Reset the password"
msgstr "Réinitialiser le mot de passe"

msgid "Enter your email address and we will send you a link to reset your password."
msgstr "Entrez votre adresse e-mail et nous vous enverrons un lien pour réinitialiser votre mot de passe."

msgid "Send the reset link"
msgstr "Envoyer le lien de réinitialisation"

msgid "Back to login"
msgstr "Retour à la connexion"

msgid "If an account with this email exists, a reset link has been sent."
msgstr "Si un compte avec cet e-mail existe, un lien de réinitialisation a été envoyé."

msgid "Choose a new password"
msgstr "Choisir un nouveau mot de passe"

msgid "Please enter your new password below."
msgstr "Veuillez entrer votre nouveau mot de passe ci-dessous."

msgid "New password"
msgstr "Nouveau mot de passe"

msgid "Confirm the new password"
msgstr "Confirmer le nouveau mot de passe"

msgid "Reset the password"
msgstr "Réinitialiser le mot de passe"

msgid "Missing data."
msgstr "Données manquantes."

msgid "The link is invalid or has expired."
msgstr "Le lien est invalide ou a expiré."

msgid "The password does not meet security criteria."
msgstr "Le mot de passe ne respecte pas les critères de sécurité."

msgid "User not found."
msgstr "Utilisateur non trouvé."

msgid "Welcome - Bienvenue"
msgstr "Bienvenue"

msgid "Please select your language. / Veuillez sélectionner votre langue."
msgstr "Veuillez sélectionner votre langue."

msgid "Welcome / Bienvenue"
msgstr "Bienvenue"

msgid "Business Logo"
msgstr "Logo Business"

msgid "Set Profile Photo"
msgstr "Définir la photo de profil"

msgid "Ignore"
msgstr "Ignorer"

msgid "Drag & drop or click to upload"
msgstr "Glisser-déposer ou cliquer pour uploader"

msgid "Choose Photo"
msgstr "Choisir une photo"

msgid "Save"
msgstr "Sauvegarder"

msgid "Cancel"
msgstr "Annuler"

msgid "Photo saved!"
msgstr "Photo sauvegardée !"

msgid "No file"
msgstr "Aucun fichier"

msgid "Invalid image"
msgstr "Image invalide"

msgid "File save error"
msgstr "Erreur de sauvegarde de fichier"

msgid "Settings"
msgstr "Paramètres"

msgid "Language"
msgstr "Langue"

msgid "Change the application language"
msgstr "Changer la langue de l'application"

msgid "Modify information"
msgstr "Modifier les informations"

msgid "Username, email"
msgstr "Nom d'utilisateur, e-mail"

msgid "Security and password"
msgstr "Sécurité et mot de passe"

msgid "Change your password"
msgstr "Changer votre mot de passe"

msgid "Change account"
msgstr "Changer de compte"

msgid "Log out"
msgstr "Se déconnecter"

msgid "Delete account"
msgstr "Supprimer le compte"

msgid "This action is irreversible"
msgstr "Cette action est irréversible"

msgid "Modify information"
msgstr "Modifier les informations"

msgid "Save"
msgstr "Sauvegarder"

msgid "This username is already taken."
msgstr "Ce nom d'utilisateur est déjà pris."

msgid "This email address is already in use."
msgstr "Cette adresse e-mail est déjà utilisée."

msgid "Profile updated successfully!"
msgstr "Profil mis à jour avec succès !"

msgid "Change the password"
msgstr "Changer le mot de passe"

msgid "Current password"
msgstr "Mot de passe actuel"

msgid "New password"
msgstr "Nouveau mot de passe"

msgid "Update"
msgstr "Mettre à jour"

msgid "The current password is incorrect."
msgstr "Le mot de passe actuel est incorrect."

msgid "The new password does not meet security criteria."
msgstr "Le nouveau mot de passe ne respecte pas les critères de sécurité."

msgid "Password changed successfully!"
msgstr "Mot de passe modifié avec succès !"

msgid "Are you absolutely certain?"
msgstr "Êtes-vous absolument certain ?"

msgid "This action cannot be undone. Your account and all your data will be permanently deleted."
msgstr "Cette action ne peut pas être annulée. Votre compte et toutes vos données seront définitivement supprimées."

msgid "Confirm with your password"
msgstr "Confirmer avec votre mot de passe"

msgid "Cancel"
msgstr "Annuler"

msgid "Permanently delete"
msgstr "Supprimer définitivement"

msgid "The password is incorrect."
msgstr "Le mot de passe est incorrect."

msgid "Account deleted successfully."
msgstr "Compte supprimé avec succès."

msgid "Attention: This action is irreversible. Do you really want to continue?"
msgstr "Attention : Cette action est irréversible. Voulez-vous vraiment continuer ?"

msgid "Language updated successfully!"
msgstr "Langue mise à jour avec succès !"

msgid "Invalid language selected."
msgstr "Langue sélectionnée invalide."

msgid "An error occurred while sending the file: %(message)s"
msgstr "Une erreur est survenue lors de l'envoi du fichier : %(message)s"

msgid "My ads"
msgstr "Mes annonces"

msgid "Actions"
msgstr "Actions"

msgid "Hide all"
msgstr "Masquer tout"

msgid "Show all"
msgstr "Afficher tout"

msgid "Delete all"
msgstr "Tout supprimer"

msgid "Hide the selection"
msgstr "Masquer la sélection"

msgid "Show the selection"
msgstr "Afficher la sélection"

msgid "Delete the selection"
msgstr "Supprimer la sélection"

msgid "Cancel the selection"
msgstr "Annuler la sélection"

msgid "Are you sure you want to delete this ad?"
msgstr "Êtes-vous sûr de vouloir supprimer cette annonce ?"

msgid "Hide"
msgstr "Masquer"

msgid "Show"
msgstr "Afficher"

msgid "Edit"
msgstr "Modifier"

msgid "Delete"
msgstr "Supprimer"

msgid "No ad selected."
msgstr "Aucune annonce sélectionnée."

msgid "%(count)s ad(s) deleted."
msgstr "%(count)s annonce(s) supprimée(s)."

msgid "Invalid action or selection."
msgstr "Action ou sélection invalide."

msgid "Visibility of %(count)s ad(s) updated."
msgstr "Visibilité de %(count)s annonce(s) mise à jour."

msgid "Hide/Show: Allows to make an ad temporarily invisible to other users."
msgstr "Masquer/Afficher : Permet de rendre une annonce temporairement invisible aux autres utilisateurs."

msgid "Edit: Opens the editing form to change the title, description or photos."
msgstr "Modifier : Ouvre le formulaire d'édition pour changer le titre, la description ou les photos."

msgid "Delete: Permanently deletes the ad."
msgstr "Supprimer : Supprime définitivement l'annonce."

msgid "Multiple Selection: Press and hold (on mobile) or use the menu at the top right to select multiple ads and perform bulk actions (hide, show, delete)."
msgstr "Sélection multiple : Appuyez longuement (sur mobile) ou utilisez le menu en haut à droite pour sélectionner plusieurs annonces et effectuer des actions en masse (masquer, afficher, supprimer)."

msgid "Clear the list"
msgstr "Vider la liste"

msgid "Are you sure you want to clear your favorites list? This action is irreversible."
msgstr "Êtes-vous sûr de vouloir vider votre liste de favoris ? Cette action est irréversible."

msgid "Your favorites list has been cleared."
msgstr "Votre liste de favoris a été vidée."

msgid "Network error during deletion."
msgstr "Erreur réseau lors de la suppression."

msgid "You have no ad in your favorites."
msgstr "Vous n'avez aucune annonce dans vos favoris."

msgid "Loading..."
msgstr "Chargement..."

msgid "Network error."
msgstr "Erreur réseau."

msgid "My Messages"
msgstr "Mes messages"

msgid "Conversations"
msgstr "Conversations"

msgid "Your messaging"
msgstr "Votre messagerie"

msgid "Select a conversation to start."
msgstr "Sélectionnez une conversation pour commencer."

msgid "No conversation."
msgstr "Aucune conversation."

msgid "Write your message..."
msgstr "Écrivez votre message..."

msgid "Attach a file"
msgstr "Joindre un fichier"

msgid "Voice message"
msgstr "Message vocal"

msgid "Cancel"
msgstr "Annuler"

msgid "Pause"
msgstr "Pause"

msgid "Send the voice message"
msgstr "Envoyer le message vocal"

msgid "Cancel the response"
msgstr "Annuler la réponse"

msgid "Rate the user"
msgstr "Noter l'utilisateur"

msgid "What rating would you give to"
msgstr "Quelle note donneriez-vous à"

msgid "Send the evaluation"
msgstr "Envoyer l'évaluation"

msgid "Add a comment (optional)"
msgstr "Ajouter un commentaire (optionnel)"

msgid "Please select a rating."
msgstr "Veuillez sélectionner une note."

msgid "Thank you for your evaluation!"
msgstr "Merci pour votre évaluation !"

msgid "Socket.IO global connected."
msgstr "Socket.IO connecté globalement."

msgid "You have received a media."
msgstr "Vous avez reçu un média."

msgid "New message from %(username)s"
msgstr "Nouveau message de %(username)s"

msgid "Start the conversation!"
msgstr "Commencez la conversation !"

msgid "Invalid time"
msgstr "Heure invalide"

msgid "Invalid chatroom ID"
msgstr "ID de conversation invalide"

msgid "Chatroom not found or user not a participant"
msgstr "Conversation non trouvée ou utilisateur non participant"

msgid "Empty message"
msgstr "Message vide"

msgid "User not authenticated"
msgstr "Utilisateur non authentifié"

msgid "Message deleted"
msgstr "Message supprimé"

msgid "Reply"
msgstr "Répondre"

msgid "Delete"
msgstr "Supprimer"

msgid "Do you really want to delete this message?"
msgstr "Voulez-vous vraiment supprimer ce message ?"

msgid "Photo"
msgstr "Photo"

msgid "Voice message"
msgstr "Message vocal"

msgid "Attached file"
msgstr "Pièce jointe"

msgid "Recording..."
msgstr "Enregistrement..."

msgid "is typing..."
msgstr "est en train d'écrire..."

msgid "is recording..."
msgstr "est en train d'enregistrer..."

msgid "Please log in to see your messages."
msgstr "Veuillez vous connecter pour voir vos messages."

msgid "Loading..."
msgstr "Chargement..."

msgid "Starting the conversation..."
msgstr "Démarrage de la conversation..."

msgid "Error creating chat."
msgstr "Erreur lors de la création du chat."

msgid "Launching chat..."
msgstr "Lancement du chat..."

msgid "Contact by Chat"
msgstr "Contacter par chat"

msgid "You must be logged in to contact the author."
msgstr "Vous devez être connecté pour contacter l'auteur."

msgid "This is your ad. You can edit it here."
msgstr "Ceci est votre annonce. Vous pouvez la modifier ici."

msgid "Contact via Message"
msgstr "Contacter via message"

msgid "My Favorites"
msgstr "Mes favoris"

msgid "Clear the list"
msgstr "Vider la liste"

msgid "Are you sure you want to clear your favorites list? This action is irreversible."
msgstr "Êtes-vous sûr de vouloir vider votre liste de favoris ? Cette action est irréversible."

msgid "Your favorites list has been cleared."
msgstr "Votre liste de favoris a été vidée."

msgid "Network error during deletion."
msgstr "Erreur réseau lors de la suppression."

msgid "You have no ad in your favorites."
msgstr "Vous n'avez aucune annonce dans vos favoris."

msgid "Loading..."
msgstr "Chargement..."

msgid "Network error."
msgstr "Erreur réseau."

msgid "Help Center"
msgstr "Centre d'aide"

msgid "Welcome to the Business usage guide. Find here all the answers to your questions."
msgstr "Bienvenue dans le guide d'utilisation de Business. Trouvez ici toutes les réponses à vos questions."

msgid "Table of contents"
msgstr "Table des matières"

msgid "1. Quick Start"
msgstr "1. Démarrage rapide"

msgid "2. Understanding an Ad"
msgstr "2. Comprendre une annonce"

msgid "3. Manage Ads"
msgstr "3. Gérer les annonces"

msgid "4. Use Messaging"
msgstr "4. Utiliser la messagerie"

msgid "5. Manage your Account"
msgstr "5. Gérer votre compte"

msgid "Create an account and log in"
msgstr "Créer un compte et se connecter"

msgid "To enjoy all features, you must first create an account. Click on the user icon at the top right, then on \"Register\". Fill in the form with a username, a valid email address and a secure password. A confirmation email will be sent to you to activate your account."
msgstr "Pour profiter de toutes les fonctionnalités, vous devez d'abord créer un compte. Cliquez sur l'icône utilisateur en haut à droite, puis sur \"S'inscrire\". Remplissez le formulaire avec un nom d'utilisateur, une adresse e-mail valide et un mot de passe sécurisé. Un e-mail de confirmation vous sera envoyé pour activer votre compte."

msgid "Once your account is activated, you can log in via the same user menu by clicking on \"Login\"."
msgstr "Une fois votre compte activé, vous pouvez vous connecter via le même menu utilisateur en cliquant sur \"Connexion\"."

msgid "The ad cards have been designed to give you essential information at a glance."
msgstr "Les cartes d'annonces ont été conçues pour vous donner les informations essentielles d'un coup d'œil."

msgid "Author Information:"
msgstr "Informations sur l'auteur :"

msgid "At the bottom left, you will find the profile picture and the name of the user who published the ad."
msgstr "En bas à gauche, vous trouverez la photo de profil et le nom de l'utilisateur qui a publié l'annonce."

msgid "Interest Count:"
msgstr "Nombre d'intérêts :"

msgid "In the center, this number indicates how many people have started a conversation about this ad. It is a good indicator of its popularity."
msgstr "Au centre, ce nombre indique combien de personnes ont commencé une conversation sur cette annonce. C'est un bon indicateur de sa popularité."

msgid "View Count:"
msgstr "Nombre de vues :"

msgid "At the bottom right, this shows how many times the ad has been viewed in detail."
msgstr "En bas à droite, cela montre combien de fois l'annonce a été consultée en détail."

msgid "Interactions on your Profile"
msgstr "Interactions sur votre profil"

msgid "On your profile page, the \"interactions\" counter shows the total number of interests accumulated on all your ads. It reflects your activity and the attractiveness of what you offer on the platform."
msgstr "Sur votre page de profil, le compteur \"interactions\" montre le nombre total d'intérêts accumulés sur toutes vos annonces. Il reflète votre activité et l'attractivité de ce que vous proposez sur la plateforme."

msgid "Create an ad"
msgstr "Créer une annonce"

msgid "Click on the \"Create\" icon (⦁). You will first have to choose if you offer a Service or an Object. Then fill in the form by giving a clear title, a detailed description, and specifying if it is an offer or a request. You can add several photos to your ad."
msgstr "Cliquez sur l'icône \"Créer\" (⦁). Vous devrez d'abord choisir si vous proposez un Service ou un Objet. Puis remplissez le formulaire en donnant un titre clair, une description détaillée, et en spécifiant s'il s'agit d'une offre ou d'une demande. Vous pouvez ajouter plusieurs photos à votre annonce."

msgid "Manage \"My Ads\""
msgstr "Gérer \"Mes annonces\""

msgid "This section groups all the ads you have published. For each ad, you can:"
msgstr "Cette section regroupe toutes les annonces que vous avez publiées. Pour chaque annonce, vous pouvez :"

msgid "Hide/Show:"
msgstr "Masquer/Afficher :"

msgid "Allows to make an ad temporarily invisible to other users."
msgstr "Permet de rendre une annonce temporairement invisible aux autres utilisateurs."

msgid "Edit:"
msgstr "Modifier :"

msgid "Opens the editing form to change the title, description or photos."
msgstr "Ouvre le formulaire d'édition pour changer le titre, la description ou les photos."

msgid "Delete:"
msgstr "Supprimer :"

msgid "Permanently deletes the ad."
msgstr "Supprime définitivement l'annonce."

msgid "Multiple Selection:"
msgstr "Sélection multiple :"

msgid "Press and hold (on mobile) or use the menu at the top right to select multiple ads and perform bulk actions (hide, show, delete)."
msgstr "Appuyez longuement (sur mobile) ou utilisez le menu en haut à droite pour sélectionner plusieurs annonces et effectuer des actions en masse (masquer, afficher, supprimer)."

msgid "Messaging allows you to chat privately and securely with other users."
msgstr "La messagerie vous permet de discuter en privé et en toute sécurité avec d'autres utilisateurs."

msgid "Start a conversation"
msgstr "Démarrer une conversation"

msgid "To contact a user, go to one of his ads and click on the \"Contact by Chat\" button. This will create a new conversation in your messaging and increase the ad's interest count by one."
msgstr "Pour contacter un utilisateur, allez sur l'une de ses annonces et cliquez sur le bouton \"Contacter par chat\". Cela créera une nouvelle conversation dans votre messagerie et augmentera le compteur d'intérêts de l'annonce d'un."

msgid "Features"
msgstr "Fonctionnalités"

msgid "Text, voice and file messages:"
msgstr "Messages texte, vocal et fichier :"

msgid "You can send written messages, record voice notes by holding the microphone icon, or attach files (paperclip icon)."
msgstr "Vous pouvez envoyer des messages écrits, enregistrer des notes vocales en maintenant l'icône micro, ou joindre des fichiers (icône trombone)."

msgid "Reply to a message:"
msgstr "Répondre à un message :"

msgid "Hover over a message to display a reply icon. Click on it to quote this message in your response."
msgstr "Survolez un message pour afficher l'icône de réponse. Cliquez dessus pour citer ce message dans votre réponse."

msgid "Rate a user:"
msgstr "Noter un utilisateur :"

msgid "After an interaction, you can leave a rating to your interlocutor thanks to the \"Rate\" button at the top of the conversation."
msgstr "Après une interaction, vous pouvez laisser une note à votre interlocuteur grâce au bouton \"Noter\" en haut de la conversation."

msgid "The Settings page"
msgstr "La page Paramètres"

msgid "Accessible from the user menu, the \"Settings\" page allows you to control your account. You can:"
msgstr "Accessible depuis le menu utilisateur, la page \"Paramètres\" vous permet de contrôler votre compte. Vous pouvez :"

msgid "Change the application language."
msgstr "Changer la langue de l'application."

msgid "Modify your username and email."
msgstr "Modifier votre nom d'utilisateur et e-mail."

msgid "Change your password."
msgstr "Changer votre mot de passe."

msgid "Log out."
msgstr "Se déconnecter."

msgid "Permanently delete your account (warning, this action is irreversible)."
msgstr "Supprimer définitivement votre compte (attention, cette action est irréversible)."

msgid "has not published any ad yet."
msgstr "n'a publié aucune annonce pour le moment."

msgid "has not received any rating yet."
msgstr "n'a reçu aucune note pour le moment."

msgid "Received ratings"
msgstr "Notes reçues"

msgid "Member since"
msgstr "Membre depuis"

msgid "on"
msgstr "sur"

msgid "reviews"
msgstr "avis"

msgid "interactions"
msgstr "interactions"

msgid "Ads of"
msgstr "Annonces de"

msgid "What do you want to post?"
msgstr "Que voulez-vous publier ?"

msgid "Choose the type of your post to start."
msgstr "Choisissez le type de votre publication pour commencer."

msgid "Publish a <strong>Service</strong>"
msgstr "Publier un <strong>service</strong>"

msgid "Publish an <strong>Object</strong>"
msgstr "Publier un <strong>objet</strong>"

msgid "Ad title"
msgstr "Titre de l'annonce"

msgid "Description"
msgstr "Description"

msgid "Ad type"
msgstr "Type d'annonce"

msgid "I offer or I search?"
msgstr "J'offre ou je cherche ?"

msgid "I offer this service/object"
msgstr "J'offre ce service/objet"

msgid "I request this service/object"
msgstr "Je demande ce service/objet"

msgid "Image(s) (hold Ctrl to select multiple)"
msgstr "Image(s) (maintenez Ctrl pour sélectionner plusieurs)"

msgid "Create the ad"
msgstr "Créer l'annonce"

msgid "Please choose a type of ad (Service or Object) first."
msgstr "Veuillez d'abord choisir un type d'annonce (Service ou Objet)."

msgid "Uploading images..."
msgstr "Téléversement des images..."

msgid "Upload error for %(filename)s."
msgstr "Erreur d'upload pour %(filename)s."

msgid "Creating ad..."
msgstr "Création de l'annonce..."

msgid "Error creating ad."
msgstr "Erreur lors de la création de l'annonce."

msgid "Modify the ad"
msgstr "Modifier l'annonce"

msgid "Title"
msgstr "Titre"

msgid "Type of ad"
msgstr "Type d'annonce"

msgid "I offer"
msgstr "J'offre"

msgid "I request"
msgstr "Je demande"

msgid "Category"
msgstr "Catégorie"

msgid "Current image"
msgstr "Image actuelle"

msgid "Change or add an image"
msgstr "Changer ou ajouter une image"

msgid "Update the ad"
msgstr "Mettre à jour l'annonce"

msgid "Unable to load post data."
msgstr "Impossible de charger les données de l'annonce."

msgid "Uploading..."
msgstr "Téléversement..."

msgid "Update error for %(filename)s."
msgstr "Erreur de mise à jour pour %(filename)s."

msgid "Updating..."
msgstr "Mise à jour..."

msgid "Ad updated successfully!"
msgstr "Annonce mise à jour avec succès !"

msgid "Error updating."
msgstr "Erreur lors de la mise à jour."

msgid "Notifications"
msgstr "Notifications"

msgid "Mark all as read"
msgstr "Tout marquer comme lu"

msgid "Delete all"
msgstr "Tout supprimer"

msgid "No action"
msgstr "Aucune action"

msgid "Mark the %(count)s as read"
msgstr "Marquer les %(count)s comme lues"

msgid "Delete the %(count)s"
msgstr "Supprimer les %(count)s"

msgid "Cancel the selection"
msgstr "Annuler la sélection"

msgid "Do you really want to delete ALL your notifications?"
msgstr "Voulez-vous vraiment supprimer TOUTES vos notifications ?"

msgid "Do you really want to delete the %(count)s selected notifications?"
msgstr "Voulez-vous vraiment supprimer les %(count)s notifications sélectionnées ?"

msgid "No notifications to process."
msgstr "Aucune notification à traiter."

msgid "Notifications marked as read."
msgstr "Notifications marquées comme lues."

msgid "Notifications deleted."
msgstr "Notifications supprimées."

msgid "Network error."
msgstr "Erreur réseau."

msgid "No notification."
msgstr "Aucune notification."

msgid "User deleted"
msgstr "Utilisateur supprimé"

msgid "[User deleted]"
msgstr "[Utilisateur supprimé]"

msgid "Details of the ad"
msgstr "Détails de l'annonce"

msgid "Loading..."
msgstr "Chargement..."

msgid "Post not found"
msgstr "Annonce non trouvée"

msgid "Save"
msgstr "Sauvegarder"

msgid "Published by %(username)s on %(date)s"
msgstr "Publié par %(username)s le %(date)s"

msgid "You must be connected to contact the author."
msgstr "Vous devez être connecté pour contacter l'auteur."

msgid "This is your ad. You can modify it here."
msgstr "Ceci est votre annonce. Vous pouvez la modifier ici."

msgid "Contact via Message"
msgstr "Contacter via message"

msgid "Launching the chat..."
msgstr "Lancement du chat..."

msgid "Error creating the chat."
msgstr "Erreur lors de la création du chat."

msgid "All ads"
msgstr "Toutes les annonces"

msgid "Type :"
msgstr "Type :"

msgid "All"
msgstr "Toutes"

msgid "Offers"
msgstr "Offres"

msgid "Requests"
msgstr "Demandes"

msgid "Sort by :"
msgstr "Trier par :"

msgid "Newest"
msgstr "Plus récentes"

msgid "Oldest"
msgstr "Plus anciennes"

msgid "Services"
msgstr "Services"

msgid "Objects"
msgstr "Objets"

msgid "No ad matches your search."
msgstr "Aucune annonce ne correspond à votre recherche."

msgid "All Ads"
msgstr "Toutes les annonces"

msgid "Profile of %(username)s"
msgstr "Profil de %(username)s"

msgid "has not published any ad yet."
msgstr "n'a publié aucune annonce pour le moment."

msgid "has not received any rating yet."
msgstr "n'a reçu aucune note pour le moment."

msgid "Received ratings (%(count)s)"
msgstr "Notes reçues (%(count)s)"

msgid "Member since %(date)s"
msgstr "Membre depuis %(date)s"

msgid "%(rating)s on 5 (%(count)s reviews)"
msgstr "%(rating)s sur 5 (%(count)s avis)"

msgid "%(count)s interactions"
msgstr "%(count)s interactions"

msgid "Ads of %(username)s"
msgstr "Annonces de %(username)s"

msgid "Contact by Chat"
msgstr "Contacter par chat"

msgid "View photo"
msgstr "Voir la photo"

msgid "View the profile"
msgstr "Voir le profil"

msgid "%(count)s people interact with this ad."
msgstr "%(count)s personnes interagissent avec cette annonce."

msgid "This ad has been viewed %(count)s times."
msgstr "Cette annonce a été consultée %(count)s fois."

msgid "View interactions"
msgstr "Voir les interactions"

msgid "View views"
msgstr "Voir les vues"

msgid "Missing required fields"
msgstr "Champs requis manquants"

msgid "Password does not meet security criteria."
msgstr "Le mot de passe ne respecte pas les critères de sécurité."

msgid "This username already exists"
msgstr "Ce nom d'utilisateur existe déjà"

msgid "This email address is already in use"
msgstr "Cette adresse e-mail est déjà utilisée"

msgid "Registration successful! Please check your email to confirm your account."
msgstr "Inscription réussie ! Vérifiez votre e-mail pour confirmer votre compte."

msgid "Your account has not been confirmed. Please check your email."
msgstr "Votre compte n'a pas été confirmé. Vérifiez votre e-mail."

msgid "Incorrect email address or password."
msgstr "Adresse e-mail ou mot de passe incorrect."

msgid "Login successful"
msgstr "Connexion réussie"

msgid "No file part"
msgstr "Aucune partie fichier"

msgid "Invalid or disallowed file"
msgstr "Fichier invalide ou non autorisé"

msgid "Post not found"
msgstr "Annonce non trouvée"

msgid "has added your ad '%(title)s' to favorites."
msgstr "a ajouté votre annonce '%(title)s' aux favoris."

msgid "Unauthorized"
msgstr "Non autorisé"

msgid "Action not authorized"
msgstr "Action non autorisée"

msgid "Favorites list cleared."
msgstr "Liste de favoris vidée."

msgid "An error occurred."
msgstr "Une erreur est survenue."

msgid "Chatroom not found or user not a participant"
msgstr "Conversation non trouvée ou utilisateur non participant"

msgid "Invalid action"
msgstr "Action invalide"

msgid "If an account with this email exists, a reset link has been sent."
msgstr "Si un compte avec cet e-mail existe, un lien de réinitialisation a été envoyé."

msgid "Missing data."
msgstr "Données manquantes."

msgid "The link is invalid or has expired."
msgstr "Le lien est invalide ou a expiré."

msgid "The password does not meet security criteria."
msgstr "Le mot de passe ne respecte pas les critères de sécurité."

msgid "User not found."
msgstr "Utilisateur non trouvé."

msgid "Notification not found"
msgstr "Notification non trouvée"

msgid "Invalid action."
msgstr "Action invalide."

msgid "No notifications to process."
msgstr "Aucune notification à traiter."

msgid "Notifications marked as read."
msgstr "Notifications marquées comme lues."

msgid "Notifications deleted."
msgstr "Notifications supprimées."

msgid "Language updated successfully!"
msgstr "Langue mise à jour avec succès !"

msgid "Invalid language selected."
msgstr "Langue sélectionnée invalide."

msgid "This username is already taken."
msgstr "Ce nom d'utilisateur est déjà pris."

msgid "This email address is already in use."
msgstr "Cette adresse e-mail est déjà utilisée."

msgid "Profile updated successfully!"
msgstr "Profil mis à jour avec succès !"

msgid "The current password is incorrect."
msgstr "Le mot de passe actuel est incorrect."

msgid "The new password does not meet security criteria."
msgstr "Le nouveau mot de passe ne respecte pas les critères de sécurité."

msgid "Password changed successfully!"
msgstr "Mot de passe modifié avec succès !"

msgid "The password is incorrect."
msgstr "Le mot de passe est incorrect."

msgid "Account deleted successfully."
msgstr "Compte supprimé avec succès."

msgid "No ad selected."
msgstr "Aucune annonce sélectionnée."

msgid "%(count)s ad(s) deleted."
msgstr "%(count)s annonce(s) supprimée(s)."

msgid "Invalid action or selection."
msgstr "Action ou sélection invalide."

msgid "Visibility of %(count)s ad(s) updated."
msgstr "Visibilité de %(count)s annonce(s) mise à jour."

msgid "Subscription saved."
msgstr "Abonnement sauvegardé."

msgid "User not found"
msgstr "Utilisateur non trouvé"

msgid "Resend"
msgstr "Renvoyer"

msgid "Network error on logout:"
msgstr "Erreur réseau lors de la déconnexion :"

msgid "Socket.IO global connected."
msgstr "Socket.IO connecté globalement."

msgid "Notification badge update received :"
msgstr "Mise à jour du badge de notifications reçue :"

msgid "Unread info received:"
msgstr "Infos non lues reçues :"

msgid "Failed to fetch unread info:"
msgstr "Échec du chargement des infos non lues :"

msgid "Updating badge with total:"
msgstr "Mise à jour du badge avec total :"

msgid "Error removing favorite:"
msgstr "Erreur lors de la suppression du favori :"

msgid "Search error."
msgstr "Erreur de recherche."

msgid "Error adding/removing favorite:"
msgstr "Erreur lors de l'ajout/suppression du favori :"

msgid "Loading..."
msgstr "Chargement..."

msgid "No ad found."
msgstr "Aucune annonce trouvée."

msgid "Save"
msgstr "Sauvegarder"

msgid "View photo"
msgstr "Voir la photo"

msgid "View profile"
msgstr "Voir le profil"

msgid "%(count)s people interact with this ad."
msgstr "%(count)s personnes interagissent avec cette annonce."

msgid "This ad has been viewed %(count)s times."
msgstr "Cette annonce a été consultée %(count)s fois."

msgid "View interactions"
msgstr "Voir les interactions"

msgid "View views"
msgstr "Voir les vues"

msgid "Login error:"
msgstr "Erreur de connexion :"

msgid "A network error occurred."
msgstr "Une erreur réseau est survenue."

msgid "Please log in to see your messages."
msgstr "Veuillez vous connecter pour voir vos messages."

msgid "Error loading conversations:"
msgstr "Erreur lors du chargement des conversations :"

msgid "No conversation."
msgstr "Aucune conversation."

msgid "Start the conversation!"
msgstr "Commencez la conversation !"

msgid "Invalid time"
msgstr "Heure invalide"

msgid "Loading..."
msgstr "Chargement..."

msgid "Rate"
msgstr "Noter"

msgid "Media"
msgstr "Média"

msgid "Attached image"
msgstr "Image jointe"

msgid "0:00"
msgstr "0:00"

msgid "Attached file"
msgstr "Fichier joint"

msgid "Invalid time"
msgstr "Heure invalide"

msgid "Resend"
msgstr "Renvoyer"

msgid "Reply"
msgstr "Répondre"

msgid "Delete"
msgstr "Supprimer"

msgid "Do you really want to delete this message?"
msgstr "Voulez-vous vraiment supprimer ce message ?"

msgid "Photo"
msgstr "Photo"

msgid "Voice message"
msgstr "Message vocal"

msgid "Cancel the response"
msgstr "Annuler la réponse"

msgid "Upload error:"
msgstr "Erreur d'upload :"

msgid "File send error: "
msgstr "Erreur d'envoi du fichier : "

msgid "Micro access error:"
msgstr "Erreur d'accès au micro :"

msgid "Unable to access microphone. Please check permissions."
msgstr "Impossible d'accéder au micro. Vérifiez les autorisations."

msgid "Please select a rating."
msgstr "Veuillez sélectionner une note."

msgid "Thank you for your evaluation!"
msgstr "Merci pour votre évaluation !"

msgid "Rating error:"
msgstr "Erreur d'évaluation :"

msgid "Write your message..."
msgstr "Écrivez votre message..."

msgid "Attach a file"
msgstr "Joindre un fichier"

msgid "Voice message"
msgstr "Message vocal"

msgid "Cancel"
msgstr "Annuler"

msgid "Pause"
msgstr "Pause"

msgid "Send the voice message"
msgstr "Envoyer le message vocal"

msgid "is typing..."
msgstr "est en train d'écrire..."

msgid "is recording..."
msgstr "est en train d'enregistrer..."

msgid "Socket.IO Connected."
msgstr "Socket.IO connecté."

msgid "Message deleted"
msgstr "Message supprimé"

msgid "My ads"
msgstr "Mes annonces"

msgid "Actions"
msgstr "Actions"

msgid "Hide all"
msgstr "Masquer tout"

msgid "Show all"
msgstr "Afficher tout"

msgid "Delete all"
msgstr "Tout supprimer"

msgid "Hide the selection"
msgstr "Masquer la sélection"

msgid "Show the selection"
msgstr "Afficher la sélection"

msgid "Delete the selection"
msgstr "Supprimer la sélection"

msgid "Cancel the selection"
msgstr "Annuler la sélection"

msgid "Are you sure you want to delete this ad?"
msgstr "Êtes-vous sûr de vouloir supprimer cette annonce ?"

msgid "Hide"
msgstr "Masquer"

msgid "Show"
msgstr "Afficher"

msgid "Edit"
msgstr "Modifier"

msgid "Delete"
msgstr "Supprimer"

msgid "No ad selected."
msgstr "Aucune annonce sélectionnée."

msgid "%(count)s ad(s) deleted."
msgstr "%(count)s annonce(s) supprimée(s)."

msgid "Invalid action or selection."
msgstr "Action ou sélection invalide."

msgid "Visibility of %(count)s ad(s) updated."
msgstr "Visibilité de %(count)s annonce(s) mise à jour."

msgid "Network error."
msgstr "Erreur réseau."

msgid "Hide/Show: Allows to make an ad temporarily invisible to other users."
msgstr "Masquer/Afficher : Permet de rendre une annonce temporairement invisible aux autres utilisateurs."

msgid "Edit: Opens the editing form to change the title, description or photos."
msgstr "Modifier : Ouvre le formulaire d'édition pour changer le titre, la description ou les photos."

msgid "Delete: Permanently deletes the ad."
msgstr "Supprimer : Supprime définitivement l'annonce."

msgid "Multiple Selection: Press and hold (on mobile) or use the menu at the top right to select multiple ads and perform bulk actions (hide, show, delete)."
msgstr "Sélection multiple : Appuyez longuement (sur mobile) ou utilisez le menu en haut à droite pour sélectionner plusieurs annonces et effectuer des actions en masse (masquer, afficher, supprimer)."

msgid "Clear the list"
msgstr "Vider la liste"

msgid "Are you sure you want to clear your favorites list? This action is irreversible."
msgstr "Êtes-vous sûr de vouloir vider votre liste de favoris ? Cette action est irréversible."

msgid "Your favorites list has been cleared."
msgstr "Votre liste de favoris a été vidée."

msgid "Network error during deletion."
msgstr "Erreur réseau lors de la suppression."

msgid "You have no ad in your favorites."
msgstr "Vous n'avez aucune annonce dans vos favoris."

msgid "Loading..."
msgstr "Chargement..."

msgid "Network error."
msgstr "Erreur réseau."

msgid "My Messages"
msgstr "Mes messages"

msgid "Conversations"
msgstr "Conversations"

msgid "Your messaging"
msgstr "Votre messagerie"

msgid "Select a conversation to start."
msgstr "Sélectionnez une conversation pour commencer."

msgid "No conversation."
msgstr "Aucune conversation."

msgid "Write your message..."
msgstr "Écrivez votre message..."

msgid "Attach a file"
msgstr "Joindre un fichier"

msgid "Voice message"
msgstr "Message vocal"

msgid "Cancel"
msgstr "Annuler"

msgid "Pause"
msgstr "Pause"

msgid "Send the voice message"
msgstr "Envoyer le message vocal"

msgid "Cancel the response"
msgstr "Annuler la réponse"

msgid "Rate the user"
msgstr "Noter l'utilisateur"

msgid "What rating would you give to"
msgstr "Quelle note donneriez-vous à"

msgid "Send the evaluation"
msgstr "Envoyer l'évaluation"

msgid "Add a comment (optional)"
msgstr "Ajouter un commentaire (optionnel)"

msgid "Please select a rating."
msgstr "Veuillez sélectionner une note."

msgid "Thank you for your evaluation!"
msgstr "Merci pour votre évaluation !"

msgid "Socket.IO global connected."
msgstr "Socket.IO connecté globalement."

msgid "You have received a media."
msgstr "Vous avez reçu un média."

msgid "New message from %(username)s"
msgstr "Nouveau message de %(username)s"

msgid "Start the conversation!"
msgstr "Commencez la conversation !"

msgid "Invalid time"
msgstr "Heure invalide"

msgid "Invalid chatroom ID"
msgstr "ID de conversation invalide"

msgid "Chatroom not found or user not a participant"
msgstr "Conversation non trouvée ou utilisateur non participant"

msgid "Empty message"
msgstr "Message vide"

msgid "User not authenticated"
msgstr "Utilisateur non authentifié"

msgid "Message deleted"
msgstr "Message supprimé"

msgid "Reply"
msgstr "Répondre"

msgid "Delete"
msgstr "Supprimer"

msgid "Do you really want to delete this message?"
msgstr "Voulez-vous vraiment supprimer ce message ?"

msgid "Photo"
msgstr "Photo"

msgid "Voice message"
msgstr "Message vocal"

msgid "Attached file"
msgstr "Pièce jointe"

msgid "Recording..."
msgstr "Enregistrement..."

msgid "is typing..."
msgstr "est en train d'écrire..."

msgid "is recording..."
msgstr "est en train d'enregistrer..."

msgid "Please log in to see your messages."
msgstr "Veuillez vous connecter pour voir vos messages."

msgid "Loading..."
msgstr "Chargement..."

msgid "Starting the conversation..."
msgstr "Démarrage de la conversation..."

msgid "Error creating chat."
msgstr "Erreur lors de la création du chat."

msgid "Launching chat..."
msgstr "Lancement du chat..."

msgid "Contact by Chat"
msgstr "Contacter par chat"

msgid "You must be logged in to contact the author."
msgstr "Vous devez être connecté pour contacter l'auteur."

msgid "This is your ad. You can edit it here."
msgstr "Ceci est votre annonce. Vous pouvez la modifier ici."

msgid "Contact via Message"
msgstr "Contacter via message"

msgid "My Favorites"
msgstr "Mes favoris"

msgid "Clear the list"
msgstr "Vider la liste"

msgid "Are you sure you want to clear your favorites list? This action is irreversible."
msgstr "Êtes-vous sûr de vouloir vider votre liste de favoris ? Cette action est irréversible."

msgid "Your favorites list has been cleared."
msgstr "Votre liste de favoris a été vidée."

msgid "Network error during deletion."
msgstr "Erreur réseau lors de la suppression."

msgid "You have no ad in your favorites."
msgstr "Vous n'avez aucune annonce dans vos favoris."

msgid "Loading..."
msgstr "Chargement..."

msgid "Network error."
msgstr "Erreur réseau."

msgid "Help Center"
msgstr "Centre d'aide"

msgid "Welcome to the Business usage guide. Find here all the answers to your questions."
msgstr "Bienvenue dans le guide d'utilisation de Business. Trouvez ici toutes les réponses à vos questions."

msgid "Table of contents"
msgstr "Table des matières"

msgid "1. Quick Start"
msgstr "1. Démarrage rapide"

msgid "2. Understanding an Ad"
msgstr "2. Comprendre une annonce"

msgid "3. Manage Ads"
msgstr "3. Gérer les annonces"

msgid "4. Use Messaging"
msgstr "4. Utiliser la messagerie"

msgid "5. Manage your Account"
msgstr "5. Gérer votre compte"

msgid "Create an account and log in"
msgstr "Créer un compte et se connecter"

msgid "To enjoy all features, you must first create an account. Click on the user icon at the top right, then on \"Register\". Fill in the form with a username, a valid email address and a secure password. A confirmation email will be sent to you to activate your account."
msgstr "Pour profiter de toutes les fonctionnalités, vous devez d'abord créer un compte. Cliquez sur l'icône utilisateur en haut à droite, puis sur \"S'inscrire\". Remplissez le formulaire avec un nom d'utilisateur, une adresse e-mail valide et un mot de passe sécurisé. Un e-mail de confirmation vous sera envoyé pour activer votre compte."

msgid "Once your account is activated, you can log in via the same user menu by clicking on \"Login\"."
msgstr "Une fois votre compte activé, vous pouvez vous connecter via le même menu utilisateur en cliquant sur \"Connexion\"."

msgid "The ad cards have been designed to give you essential information at a glance."
msgstr "Les cartes d'annonces ont été conçues pour vous donner les informations essentielles d'un coup d'œil."

msgid "Author Information:"
msgstr "Informations sur l'auteur :"

msgid "At the bottom left, you will find the profile picture and the name of the user who published the ad."
msgstr "En bas à gauche, vous trouverez la photo de profil et le nom de l'utilisateur qui a publié l'annonce."

msgid "Interest Count:"
msgstr "Nombre d'intérêts :"

msgid "In the center, this number indicates how many people have started a conversation about this ad. It is a good indicator of its popularity."
msgstr "Au centre, ce nombre indique combien de personnes ont commencé une conversation sur cette annonce. C'est un bon indicateur de sa popularité."

msgid "View Count:"
msgstr "Nombre de vues :"

msgid "At the bottom right, this shows how many times the ad has been viewed in detail."
msgstr "En bas à droite, cela montre combien de fois l'annonce a été consultée en détail."

msgid "Interactions on your Profile"
msgstr "Interactions sur votre profil"

msgid "On your profile page, the \"interactions\" counter shows the total number of interests accumulated on all your ads. It reflects your activity and the attractiveness of what you offer on the platform."
msgstr "Sur votre page de profil, le compteur \"interactions\" montre le nombre total d'intérêts accumulés sur toutes vos annonces. Il reflète votre activité et l'attractivité de ce que vous proposez sur la plateforme."

msgid "Create an ad"
msgstr "Créer une annonce"

msgid "Click on the \"Create\" icon (⦁). You will first have to choose if you offer a Service or an Object. Then fill in the form by giving a clear title, a detailed description, and specifying if it is an offer or a request. You can add several photos to your ad."
msgstr "Cliquez sur l'icône \"Créer\" (⦁). Vous devrez d'abord choisir si vous proposez un Service ou un Objet. Puis remplissez le formulaire en donnant un titre clair, une description détaillée, et en spécifiant s'il s'agit d'une offre ou d'une demande. Vous pouvez ajouter plusieurs photos à votre annonce."

msgid "Manage \"My Ads\""
msgstr "Gérer \"Mes annonces\""

msgid "This section groups all the ads you have published. For each ad, you can:"
msgstr "Cette section regroupe toutes les annonces que vous avez publiées. Pour chaque annonce, vous pouvez :"

msgid "Hide/Show:"
msgstr "Masquer/Afficher :"

msgid "Allows to make an ad temporarily invisible to other users."
msgstr "Permet de rendre une annonce temporairement invisible aux autres utilisateurs."

msgid "Edit:"
msgstr "Modifier :"

msgid "Opens the editing form to change the title, description or photos."
msgstr "Ouvre le formulaire d'édition pour changer le titre, la description ou les photos."

msgid "Delete:"
msgstr "Supprimer :"

msgid "Permanently deletes the ad."
msgstr "Supprime définitivement l'annonce."

msgid "Multiple Selection:"
msgstr "Sélection multiple :"

msgid "Press and hold (on mobile) or use the menu at the top right to select multiple ads and perform bulk actions (hide, show, delete)."
msgstr "Appuyez longuement (sur mobile) ou utilisez le menu en haut à droite pour sélectionner plusieurs annonces et effectuer des actions en masse (masquer, afficher, supprimer)."

msgid "Messaging allows you to chat privately and securely with other users."
msgstr "La messagerie vous permet de discuter en privé et en toute sécurité avec d'autres utilisateurs."

msgid "Start a conversation"
msgstr "Démarrer une conversation"

msgid "To contact a user, go to one of his ads and click on the \"Contact by Chat\" button. This will create a new conversation in your messaging and increase the ad's interest count by one."
msgstr "Pour contacter un utilisateur, allez sur l'une de ses annonces et cliquez sur le bouton \"Contacter par chat\". Cela créera une nouvelle conversation dans votre messagerie et augmentera le compteur d'intérêts de l'annonce d'un."

msgid "Features"
msgstr "Fonctionnalités"

msgid "Text, voice and file messages:"
msgstr "Messages texte, vocal et fichier :"

msgid "You can send written messages, record voice notes by holding the microphone icon, or attach files (paperclip icon)."
msgstr "Vous pouvez envoyer des messages écrits, enregistrer des notes vocales en maintenant l'icône micro, ou joindre des fichiers (icône trombone)."

msgid "Reply to a message:"
msgstr "Répondre à un message :"

msgid "Hover over a message to display a reply icon. Click on it to quote this message in your response."
msgstr "Survolez un message pour afficher l'icône de réponse. Cliquez dessus pour citer ce message dans votre réponse."

msgid "Rate a user:"
msgstr "Noter un utilisateur :"

msgid "After an interaction, you can leave a rating to your interlocutor thanks to the \"Rate\" button at the top of the conversation."
msgstr "Après une interaction, vous pouvez laisser une note à votre interlocuteur grâce au bouton \"Noter\" en haut de la conversation."

msgid "The Settings page"
msgstr "La page Paramètres"

msgid "Accessible from the user menu, the \"Settings\" page allows you to control your account. You can:"
msgstr "Accessible depuis le menu utilisateur, la page \"Paramètres\" vous permet de contrôler votre compte. Vous pouvez :"

msgid "Change the application language."
msgstr "Changer la langue de l'application."

msgid "Modify your username and email."
msgstr "Modifier votre nom d'utilisateur et e-mail."

msgid "Change your password."
msgstr "Changer votre mot de passe."

msgid "Log out."
msgstr "Se déconnecter."

msgid "Permanently delete your account (warning, this action is irreversible)."
msgstr "Supprimer définitivement votre compte (attention, cette action est irréversible)."

msgid "has not published any ad yet."
msgstr "n'a publié aucune annonce pour le moment."

msgid "has not received any rating yet."
msgstr "n'a reçu aucune note pour le moment."

msgid "Received ratings"
msgstr "Notes reçues"

msgid "Member since"
msgstr "Membre depuis"

msgid "on"
msgstr "sur"

msgid "reviews"
msgstr "avis"

msgid "interactions"
msgstr "interactions"

msgid "Ads of"
msgstr "Annonces de"

msgid "What do you want to post?"
msgstr "Que voulez-vous publier ?"
msgid "Push notification sent."
msgstr "Notification push envoyée."
msgid "Subscription invalid, it will be deleted."
msgstr "L'abonnement est invalide, il sera supprimé."
msgid "The link has expired. Please re-register."
msgstr "Le lien a expiré. Veuillez vous réinscrire."
msgid "The link is invalid."
msgstr "Le lien est invalide."
msgid "already_confirmed"
msgstr "already_confirmed"
msgid "confirmed"
msgstr "confirmed"
msgid "password_reset_success"
msgstr "password_reset_success"
msgid "Unauthorized"
msgstr "Non autorisé"
msgid "Post not found"
msgstr "Annonce non trouvée"
msgid "Action not authorized"
msgstr "Action non autorisée"
msgid "An error occurred."
msgstr "Une erreur est survenue."
msgid "Chatroom not found or user not a participant"
msgstr "Conversation non trouvée ou utilisateur non participant"
msgid "Invalid action"
msgstr "Action invalide"
msgid "Empty message"
msgstr "Message vide"
msgid "User not authenticated"
msgstr "Utilisateur non authentifié"
msgid "Invalid chatroom ID"
msgstr "ID de conversation invalide"
msgid "File send error: "
msgstr "Erreur d'envoi du fichier : "
msgid "Upload error:"
msgstr "Erreur d'upload :"
msgid "Micro access error:"
msgstr "Erreur d'accès au micro :"
msgid "Unable to access microphone. Please check permissions."
msgstr "Impossible d'accéder au micro. Veuillez vérifier les autorisations."
msgid "Please select a rating."
msgstr "Veuillez sélectionner une note."
msgid "Thank you for your evaluation!"
msgstr "Merci pour votre évaluation !"
msgid "Rating error:"
msgstr "Erreur d'évaluation :"
msgid "Socket.IO global connected."
msgstr "Socket.IO connecté globalement."
msgid "Notification badge update received :"
msgstr "Mise à jour du badge de notifications reçue :"
msgid "Unread info received:"
msgstr "Infos non lues reçues :"
msgid "Failed to fetch unread info:"
msgstr "Échec du chargement des infos non lues :"
msgid "Updating badge with total:"
msgstr "Mise à jour du badge avec total :"
msgid "Error removing favorite:"
msgstr "Erreur lors de la suppression du favori :"
msgid "Search error."
msgstr "Erreur de recherche."
msgid "Error adding/removing favorite:"
msgstr "Erreur lors de l'ajout/suppression du favori :"
msgid "Loading..."
msgstr "Chargement..."
msgid "No ad found."
msgstr "Aucune annonce trouvée."
msgid "Save"
msgstr "Sauvegarder"
msgid "View photo"
msgstr "Voir la photo"
msgid "View profile"
msgstr "Voir le profil"
msgid "%(count)s people interact with this ad."
msgstr "%(count)s personnes interagissent avec cette annonce."
msgid "This ad has been viewed %(count)s times."
msgstr "Cette annonce a été consultée %(count)s fois."
msgid "View interactions"
msgstr "Voir les interactions"
msgid "View views"
msgstr "Voir les vues"
msgid "Login error:"
msgstr "Erreur de connexion :"
msgid "A network error occurred."
msgstr "Une erreur réseau est survenue."
msgid "Please log in to see your messages."
msgstr "Veuillez vous connecter pour voir vos messages."
msgid "Error loading conversations:"
msgstr "Erreur lors du chargement des conversations :"
msgid "No conversation."
msgstr "Aucune conversation."
msgid "Start the conversation!"
msgstr "Commencez la conversation !"
msgid "Invalid time"
msgstr "Heure invalide"
msgid "Invalid chatroom ID"
msgstr "ID de conversation invalide"
msgid "Chatroom not found or user not a participant"
msgstr "Conversation non trouvée ou utilisateur non participant"
msgid "Empty message"
msgstr "Message vide"
msgid "User not authenticated"
msgstr "Utilisateur non authentifié"
msgid "Message deleted"
msgstr "Message supprimé"
msgid "Reply"
msgstr "Répondre"
msgid "Delete"
msgstr "Supprimer"
msgid "Do you really want to delete this message?"
msgstr "Voulez-vous vraiment supprimer ce message ?"
msgid "Photo"
msgstr "Photo"
msgid "Voice message"
msgstr "Message vocal"
msgid "Attached file"
msgstr "Pièce jointe"
msgid "Recording..."
msgstr "Enregistrement..."
msgid "is typing..."
msgstr "est en train d'écrire..."
msgid "is recording..."
msgstr "est en train d'enregistrer..."
msgid "Please log in to see your messages."
msgstr "Veuillez vous connecter pour voir vos messages."
msgid "Loading..."
msgstr "Chargement..."
msgid "Starting the conversation..."
msgstr "Démarrage de la conversation..."
msgid "Error creating chat."
msgstr "Erreur lors de la création du chat."
msgid "Launching chat..."
msgstr "Lancement du chat..."
msgid "Contact by Chat"
msgstr "Contacter par chat"
msgid "You must be logged in to contact the author."
msgstr "Vous devez être connecté pour contacter l'auteur."
msgid "This is your ad. You can edit it here."
msgstr "Ceci est votre annonce. Vous pouvez la modifier ici."
msgid "Contact via Message"
msgstr "Contacter via message"
msgid "My Favorites"
msgstr "Mes favoris"
msgid "Clear the list"
msgstr "Vider la liste"
msgid "Are you sure you want to clear your favorites list? This action is irreversible."
msgstr "Êtes-vous sûr de vouloir vider votre liste de favoris ? Cette action est irréversible."
msgid "Your favorites list has been cleared."
msgstr "Votre liste de favoris a été vidée."
msgid "Network error during deletion."
msgstr "Erreur réseau lors de la suppression."
msgid "You have no ad in your favorites."
msgstr "Vous n'avez aucune annonce dans vos favoris."
msgid "Loading..."
msgstr "Chargement..."
msgid "Network error."
msgstr "Erreur réseau."
msgid "Help Center"
msgstr "Centre d'aide"
msgid "Welcome to the Business usage guide. Find here all the answers to your questions."
msgstr "Bienvenue dans le guide d'utilisation de Business. Trouvez ici toutes les réponses à vos questions."
msgid "Table of contents"
msgstr "Table des matières"
msgid "About"
msgstr "À propos"

msgid "Change language"
msgstr "Changer de langue"

msgid "Welcome to Business!"
msgstr "Bienvenue sur Business !"

msgid "Business is a local platform for exchange and sharing. Here, you can give a second life to your objects by exchanging them, or share your skills by offering services."
msgstr "Business est une plateforme locale d'échange et de partage. Ici, vous pouvez donner une seconde vie à vos objets en les échangeant, ou partager vos compétences en proposant des services."

msgid "To start interacting with the community, discover all the features, and post your own ads, creating an account is necessary. Join us!"
msgstr "Pour commencer à interagir avec la communauté, découvrir toutes les fonctionnalités et publier vos propres annonces, la création d'un compte est nécessaire. Rejoignez-nous !"

msgid "Sign up for free"
msgstr "S'inscrire gratuitement"

msgid "6. For Visitors"
msgstr "6. Pour les visiteurs"

msgid "Discovering the Platform"
msgstr "Découvrir la plateforme"

msgid "Even without an account, you can browse the latest ads. In the navigation bar, you will find an \"About\" icon (?) that explains the concept of the application and a globe icon to change the display language."
msgstr "Même sans compte, vous pouvez parcourir les dernières annonces. Dans la barre de navigation, vous trouverez une icône \"À propos\" (?) qui explique le concept de l'application et une icône globe pour changer la langue d'affichage."

msgid "Why Register?"
msgstr "Pourquoi s'inscrire ?"

msgid "Registration is free and necessary to unlock all features: contact other members, post your own ads, save your favorites, and much more."
msgstr "L'inscription est gratuite et nécessaire pour débloquer toutes les fonctionnalités : contacter d'autres membres, publier vos propres annonces, sauvegarder vos favoris, et bien plus encore."

msgid "Language:"
msgstr "Langue :"

msgid "Change the application language for your account. This choice will be saved for your future visits."
msgstr "Changez la langue de l'application pour votre compte. Ce choix sera sauvegardé pour vos futures visites."

msgid "Theme:"
msgstr "Thème :"

msgid "Switch between light and dark themes using the sun/moon icon in the top navigation bar."
msgstr "Basculez entre les thèmes clair et sombre en utilisant l'icône soleil/lune dans la barre de navigation supérieure."
# Nouvelles traductions pour la page d'aide et autres
msgid "1. First Steps on Business"
msgstr "1. Premiers pas sur Business"

msgid "2. Posting and Managing Your Ads"
msgstr "2. Publier et Gérer Vos Annonces"

msgid "3. Interacting with the Community"
msgstr "3. Interagir avec la Communauté"

msgid "4. Using Private Messaging"
msgstr "4. Utiliser la Messagerie Privée"

msgid "5. Managing Your Account and Settings"
msgstr "5. Gérer Votre Compte et Paramètres"

msgid "6. For Visitors (Without an Account)"
msgstr "6. Pour les Visiteurs (Sans Compte)"

msgid "Your Department"
msgstr "Votre Département"

msgid "Detecting location..."
msgstr "Détection de la localisation..."

msgid "Press to select"
msgstr "Appuyez pour sélectionner"

msgid "No locations available"
msgstr "Aucune localisation disponible"

msgid "No results found"
msgstr "Aucun résultat trouvé"

msgid "Select your department..."
msgstr "Sélectionnez votre département..."

msgid "Current position"
msgstr "Position actuelle"

msgid "Socket.IO Connected."
msgstr "Socket.IO Connecté."
# Strings from JavaScript files

msgid "Publishing..."
msgstr "Publication en cours..."

msgid "Uploading..."
msgstr "Téléchargement en cours..."

msgid "Updating..."
msgstr "Mise à jour en cours..."

msgid "Are you sure you want to delete this ad?"
msgstr "Êtes-vous sûr de vouloir supprimer cette annonce ?"

msgid "Are you sure you want to hide this ad?"
msgstr "Êtes-vous sûr de vouloir masquer cette annonce ?"

msgid "Are you sure you want to show this ad?"
msgstr "Êtes-vous sûr de vouloir afficher cette annonce ?"

msgid "Failed to delete ad."
msgstr "Échec de la suppression de l'annonce."

msgid "An error occurred while deleting the ad."
msgstr "Une erreur s'est produite lors de la suppression de l'annonce."

msgid "Failed to update visibility."
msgstr "Échec de la mise à jour de la visibilité."

msgid "An error occurred while updating the visibility."
msgstr "Une erreur s'est produite lors de la mise à jour de la visibilité."

msgid "Hide selection"
msgstr "Masquer la sélection"

msgid "Show selection"
msgstr "Afficher la sélection"

msgid "Delete selection"
msgstr "Supprimer la sélection"

msgid "Cancel selection"
msgstr "Annuler la sélection"

msgid "Hide all selected ads?"
msgstr "Masquer toutes les annonces sélectionnées ?"

msgid "Show all selected ads?"
msgstr "Afficher toutes les annonces sélectionnées ?"

msgid "Permanently delete the selected ads?"
msgstr "Supprimer définitivement les annonces sélectionnées ?"

msgid "Failed to perform action."
msgstr "Échec de l'exécution de l'action."

msgid "You haven't posted any ads yet. Time to create your first one!"
msgstr "Vous n'avez pas encore publié d'annonces. Il est temps de créer votre première !"

msgid "Press to select"
msgstr "Appuyez pour sélectionner"

msgid "Detecting location..."
msgstr "Détection de l'emplacement..."

msgid "No locations available"
msgstr "Aucun emplacement disponible"

msgid "No results found"
msgstr "Aucun résultat trouvé"

msgid "Select your department..."
msgstr "Sélectionnez votre département..."

msgid "Select your department... (Geolocation blocked)"
msgstr "Sélectionnez votre département... (Géolocalisation bloquée)"

msgid "Select your department... (Allow location access?)"
msgstr "Sélectionnez votre département... (Autoriser l'accès à la localisation ?)"

msgid "Select your department... (Not supported)"
msgstr "Sélectionnez votre département... (Non supporté)"

msgid "Current position"
msgstr "Position actuelle"

msgid "Error loading locations"
msgstr "Erreur lors du chargement des emplacements"

msgid "Me"
msgstr "Moi"

msgid "Gallery"
msgstr "Galerie"

msgid "Camera"
msgstr "Caméra"

msgid "Document"
msgstr "Document"

msgid "Emojis"
msgstr "Émojis"

msgid "Attach file"
msgstr "Joindre un fichier"

msgid "Message"
msgstr "Message"

msgid "Video"
msgstr "Vidéo"

msgid "Delete messages?"
msgstr "Supprimer les messages ?"

msgid "Are you sure you want to delete this conversation? This action is irreversible."
msgstr "Êtes-vous sûr de vouloir supprimer cette conversation ? Cette action est irréversible."

msgid "Error during deletion."
msgstr "Erreur lors de la suppression."

msgid "A network error has occurred."
msgstr "Une erreur réseau s'est produite."

msgid "Delete conversation"
msgstr "Supprimer la conversation"

msgid "Mark the %(count)s as read"
msgstr "Marquer les %(count)s comme lus"

msgid "Delete the %(count)s"
msgstr "Supprimer les %(count)s"

msgid "Mark as read"
msgstr "Marquer comme lu"

msgid "Delete"
msgstr "Supprimer"

msgid "Do you really want to delete ALL your notifications?"
msgstr "Voulez-vous vraiment supprimer TOUTES vos notifications ?"

msgid "Do you really want to delete the %(count)s selected notifications?"
msgstr "Voulez-vous vraiment supprimer les %(count)s notifications sélectionnées ?"

msgid "[User]"
msgstr "[Utilisateur]"

msgid "Signing up..."
msgstr "Inscription en cours..."

msgid "Please select your department."
msgstr "Veuillez sélectionner votre département."

msgid "Password reset successfully! Redirecting..."
msgstr "Mot de passe réinitialisé avec succès ! Redirection..."

msgid "Upload error"
msgstr "Erreur de téléchargement"

msgid "Do you really want to log out?"
msgstr "Voulez-vous vraiment vous déconnecter ?"

msgid "Error deleting."
msgstr "Erreur lors de la suppression."

msgid "Photo updated!"
msgstr "Photo mise à jour !"

msgid "Photo deleted."
msgstr "Photo supprimée."

msgid "What are you looking for today?"
msgstr "Que recherchez-vous aujourd'hui ?"

msgid "OK"
msgstr "OK"

msgid "Contact by message"
msgstr "Contacter par message"

# Titles from HTML/JS (Remember to replace static titles in HTML with {{ _('...') }} )

msgid "Your Title"
msgstr "Votre titre"

msgid "Delete image"
msgstr "Supprimer l'image"

msgid "Actions"
msgstr "Actions"

msgid "Sort: Newest"
msgstr "Trier : Plus récent"

msgid "Sort: Oldest"
msgstr "Trier : Plus ancien"

msgid "Type (All)"
msgstr "Type (Tout)"
msgid "Search for an object or service..."
msgstr "Rechercher un objet ou un service..."