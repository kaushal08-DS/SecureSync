from database import db


class File(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    encrypted_path = db.Column(
        db.String(255),
        nullable=False
    )

    key_path = db.Column(
        db.String(255),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id")
    )