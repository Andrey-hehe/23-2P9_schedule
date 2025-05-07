""""Этот код по созданию БД, через peewee для веб приложения"""
import peewee
import bcrypt

db = peewee.SqliteDatabase('db.db')


class BaseModel(peewee.Model):
    """Базовый класс для моделей, определяющий общую базу данных."""
    class Meta:
        """Класс для указания БД"""
        database = db


class Role(BaseModel):
    """Класс определяющий роль пользователя"""
    name = peewee.CharField(unique=True)


class User(BaseModel):
    """Класс представляет основные данные пользователя"""
    username = peewee.CharField(unique=True)
    password_hash = peewee.CharField()
    role = peewee.ForeignKeyField(Role, backref='users')

    def set_password(self, password):
        """Функция для хэширования паролей"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'),
                                           bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Функция для проверки пароля с хэшем"""
        return bcrypt.checkpw(password.encode('utf-8'),
                              self.password_hash.encode('utf-8'))


def create_tables():
    """Создает таблицы в базе данных, если их еще нет."""
    with db:
        db.create_tables([Role, User])


def create_initial_user():
    """Создает первую учетную запись с ролью 'Сотрудник учебного отдела'"""
    try:
        employee_role, _ = Role.get_or_create(name='Сотрудник'
                                                   'учебного отдела')
        Role.get_or_create(name='Преподаватель')
        Role.get_or_create(name='Студент')

        if User.select().join(Role).where(Role.name ==
                                          'Сотрудник учебного'
                                          'отдела').exists():
            print("Учетная запись сотрудника учебного отдела уже существует.")
            return

        initial_user = User(username='админ', role=employee_role)
        initial_user.set_password('пароль')
        initial_user.save()
        print("Создана первая учетная запись 'Сотрудник учебного отдела'.")

    except peewee.IntegrityError:
        print("Ошибка при создании начальной учетной записи")


def add_teacher_account(username, password, creating_user):
    """Добавляет учетную запись преподавателя.

    Аргументы:
        username: Имя пользователя для новой учетной записи преподавателя.
        password: Пароль для новой учетной записи преподавателя.
        creating_user: Объект User, представляющий пользователя.
    """
    try:
        if creating_user.role.name == 'Сотрудник учебного отдела':
            teacher_role = Role.get(Role.name == 'Преподаватель')

            new_teacher = User(username=username, role=teacher_role)
            new_teacher.set_password(password)
            new_teacher.save()
            print(f"Учетная запись преподавателя '{username}' создана.")

        else:
            print("У вас неn прав для создания учетной записи преподавателя.")

    except peewee.IntegrityError:
        print(f"Ошибка: Имя пользователя '{username}' уже занято.")


def add_user_account(username, password, creating_user):
    """Добавляет учетную запись студента.

    Аргументы:
        username: Имя пользователя для новой учетной записи студента.
        password: Пароль для новой учетной записи студента.
        creating_user: Объект User, представляющий студента.
    """
    try:
        if creating_user.role.name == 'Сотрудник учебного отдела':
            student_role = Role.get(Role.name == 'Студент')

            new_student = User(username=username, role=student_role)
            new_student.set_password(password)
            new_student.save()
            print(f"Учетная запись студента '{username}' создана.")

        else:
            print("У вас нет прав для создания учетной записи студента.")

    except peewee.IntegrityError:
        print(f"Ошибка: Имя пользователя '{username}' уже занято.")


if __name__ == '__main__':
    db.connect()
    create_tables()
    create_initial_user()
