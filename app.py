import eventlet
eventlet.monkey_patch()
from flask import Flask, jsonify, request, send_from_directory, render_template, redirect, url_for, g, abort, session
from werkzeug.utils import secure_filename
#from search_service import search_service, _preprocess_text
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key-for-flask-sessions-DEV-ONLY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-jwt-secret-key-DEV-ONLY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///mydatabase.db')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
app.config['MAIL_PORT'] = os.environ.get('MAIL_PORT', 587)
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'landrydengue1@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'qsypazfsfylmpmbr')
app.config['MAIL_DEFAULT_SENDER'] = ('Business', app.config['MAIL_USERNAME'])
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
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
    password_hash = db.Column(db.String(256), nullable=False)
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
        #semantic_ids = search_service.semantic_search(search_term, k=100)
        keyword_query = Post.query.with_entities(Post.id).filter(
            Post.title.ilike(f'%{search_term}%') | Post.description.ilike(f'%{search_term}%')
        )
        keyword_ids = [item[0] for item in keyword_query.all()]
        combined_ids = list(dict.fromkeys((keyword_ids)))
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

# AJOUTE CE BLOC POUR CRÉER UNE COMMANDE PERSONNALISÉE
@app.cli.command("init-db")
def init_db_command():
    """Crée les tables de la base de données."""
    with app.app_context():
        db.create_all()
    print("Base de données initialisée !")

# TON ANCIEN BLOC RESTE INCHANGÉ, IL SERVIRA POUR LE DÉVELOPPEMENT LOCAL
if __name__ == '__main__':
    # Tu peux même garder le create_all() ici pour la facilité en local
    with app.app_context(): 
        db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)