from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('manager', 'Manager'), ('supervisor', 'Supervisor'), ('worker', 'Worker')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    assigned_to = SelectField('Assigned To', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Create Task')

class UpdateTaskForm(FlaskForm):
    comments = TextAreaField('Comments')
    completion_percentage = IntegerField('Completion Percentage', validators=[NumberRange(min=0, max=100)])
    status = SelectField('Status', choices=[('working', 'Working'), ('review', 'Review'), ('submitted', 'Submitted')])
    submit = SubmitField('Update Task')
