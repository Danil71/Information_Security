#include "mainwindow.h"
#include "sha1.h"
#include <QFile>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("SHA-1 Хеширование (Лаб. работа)");
    resize(550, 400);

    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout *main = new QVBoxLayout(central);

    //================ ДАННЫЕ СТУДЕНТА =================
    QGroupBox *groupStudent = new QGroupBox("Данные студента");
    QGridLayout *layStudent = new QGridLayout(groupStudent);

    layStudent->addWidget(new QLabel("ФИО:"), 0, 0);
    editFio = new QLineEdit("Путинцев Даниил Максимович"); layStudent->addWidget(editFio, 0, 1);
    editFio->setReadOnly(true);

    layStudent->addWidget(new QLabel("Вариант хэш-функции:"), 1, 0);
    editVariant = new QLineEdit("SHA-1");
    layStudent->addWidget(editVariant, 1, 1);
    editVariant->setReadOnly(true);

    main->addWidget(groupStudent);


    //================ ОПИСАНИЕ SHA-1 =================
    QGroupBox *groupInfo = new QGroupBox("Описание алгоритма SHA-1");
    QVBoxLayout *layInfo = new QVBoxLayout(groupInfo);

    infoText = new QTextEdit();
    infoText->setReadOnly(true);
    infoText->setText(
"SHA-1 (Secure Hash Algorithm 1) — криптографическая хеш-функция, разработанная Агентством национальной безопасности США. Она принимает сообщение произвольной длины и возвращает фиксированный хеш длиной 160 бит (20 байт), представленный как 40 шестнадцатеричных символов."
        );
    layInfo->addWidget(infoText);
    main->addWidget(groupInfo);


    //================ БЛОК ХЕШИРОВАНИЯ =================
    QGroupBox *groupHash = new QGroupBox("Хеширование файла");
    QGridLayout *layHash = new QGridLayout(groupHash);

    btnChooseFile = new QPushButton("Выбрать файл");
    layHash->addWidget(btnChooseFile, 0, 0);

    editFilePath = new QLineEdit();
    editFilePath->setPlaceholderText("Путь к файлу...");
    layHash->addWidget(editFilePath, 0, 1);

    btnHash = new QPushButton("Вычислить SHA-1");
    layHash->addWidget(btnHash, 1, 0);

    QLabel* builtinLabel = new QLabel("Встроенный SHA-1");
    QLabel* customLabel = new QLabel("Разработанный SHA-1");

    layHash->addWidget(builtinLabel, 1, 2);
    layHash->addWidget(customLabel, 2, 2);

    // Устанавливаем выравнивание для конкретных ячеек
    layHash->setAlignment(builtinLabel, Qt::AlignLeft | Qt::AlignVCenter);
    layHash->setAlignment(customLabel, Qt::AlignLeft | Qt::AlignVCenter);

    editHash = new QLineEdit();
    editHash->setPlaceholderText("Результат SHA-1 (встроенный)...");
    layHash->addWidget(editHash, 1, 1);

    ourEditHash = new QLineEdit();
    ourEditHash->setPlaceholderText("Результат SHA-1 (разработанный)...");
    layHash->addWidget(ourEditHash, 2, 1);

    btnSave = new QPushButton("Сохранить в TXT");
    layHash->addWidget(btnSave, 2, 0);

    main->addWidget(groupHash);

    //========= СВЯЗЫВАЕМ СЛОТЫ =============
    connect(btnChooseFile, &QPushButton::clicked, this, &MainWindow::chooseFile);
    connect(btnHash,       &QPushButton::clicked, this, &MainWindow::calcHash);
    connect(btnSave,       &QPushButton::clicked, this, &MainWindow::saveHash);
}


//=====================================================
// 1) Выбор файла
void MainWindow::chooseFile() {
    QString path = QFileDialog::getOpenFileName(this, "Выбор файла");
    if (!path.isEmpty()) editFilePath->setText(path);
}


//=====================================================
// 2) Вычисление SHA-1
void MainWindow::calcHash() {
    QFile file(editFilePath->text());
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Ошибка", "Не удалось открыть файл!");
        return;
    }
    QByteArray data = file.readAll();
    file.close();

    if (data.size() < 1024) {
        QMessageBox::warning(this, "Ошибка", "Файл должен быть не менее 1 КБ");
        return;
    }

    // Создаем объект SHA-1
    SHA1 sha;

    // Обновляем хеш данными файла
    // Вариант 1: Используем update с указателем и размером
    sha.update(reinterpret_cast<const unsigned char*>(data.constData()),
               static_cast<size_t>(data.size()));

    // Получаем хеш в виде строки
    QString ourHash = QString::fromStdString(sha.hexdigest());

    QByteArray hash = QCryptographicHash::hash(data, QCryptographicHash::Sha1).toHex();

    ourEditHash->setText(ourHash);
    editHash->setText(hash);
}


//=====================================================
// 3) Сохранение в .txt
void MainWindow::saveHash() {
    QString fileName = QFileDialog::getSaveFileName(this,"Сохранить", "hash.txt");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(editHash->text().toUtf8());
        file.close();
        QMessageBox::information(this,"Успешно","Хеш сохранён.");
    }
}
