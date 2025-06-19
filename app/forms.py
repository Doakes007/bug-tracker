from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import InputRequired
from wtforms.validators import DataRequired


class BugForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired()])
    description = TextAreaField('Description', validators=[InputRequired()])
    steps_to_reproduce = TextAreaField('Steps to Reproduce')
    severity = SelectField('Severity', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')])
    submit = SubmitField('Report Bug')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=100)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('dev', 'Developer'), ('qa', 'QA'), ('reporter', 'Reporter')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class AssignBugForm(FlaskForm):
    assigned_to = SelectField('Assign To', coerce=int)
    submit = SubmitField('Assign')
    
class UpdateStatusForm(FlaskForm):
    status = SelectField(
        'Status',
        choices=[
            ('New', 'New'),
            ('Assigned', 'Assigned'),
            ('In Progress', 'In Progress'),
            ('Resolved', 'Resolved'),
            ('Closed', 'Closed')
        ],
        validators=[DataRequired()]
    )

    comment = TextAreaField('Comment (optional)')  # ✅ Add this line

    submit = SubmitField('Update Status')
    
class CommentForm(FlaskForm):
    content = TextAreaField("Add Comment", validators=[DataRequired()])
    submit = SubmitField("Post")



