#include "mainwindow.h"
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QRadioButton>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressBar>
#include <QFile>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QByteArray>
#include <QFileInfo>
#include <QDebug>
#include "des.h"

#include <array>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi();
}

void MainWindow::setupUi()
{
    QWidget *w = new QWidget;
    setCentralWidget(w);

    lblStudent = new QLabel(tr("Студент: Путинцев Даниил"));
    lblVariant = new QLabel(tr("Вариант: DES в режиме CBC (Cipher Block Chaining)"));

    txtAlgorithm = new QTextEdit;
    txtAlgorithm->setReadOnly(true);
    txtAlgorithm->setMinimumHeight(150);
    txtAlgorithm->setPlainText(tr(
        "Алгоритм: DES (Data Encryption Standard) в режиме CBC.\n\n"
        "Режим CBC: каждый блок XOR'ится с предыдущим шифротекстным блоком перед шифрованием. "
        "Первоначально используется IV (initialization vector). IV генерируется случайно при шифровании "
        "и записывается в начало выходного файла. При расшифровании IV читается из начала входного файла.\n\n"
        "Ключ: 8 байт. В этой реализации ключ получается из пароля через MD5 и берутся первые 8 байт хеша.\n\n"
        "Padding: PKCS#7 (количество добавляемых байт равно числу байт заполнения, от 1 до 8).\n\n"
        "Программа поддерживает чтение/запись любых бинарных файлов (word, excel, изображения и др.)."
        ));

    // File selection
    leSource = new QLineEdit;
    leDest = new QLineEdit;
    btnSource = new QPushButton(tr("Выбрать исходный файл..."));
    btnDest = new QPushButton(tr("Выбрать файл назначения..."));

    connect(btnSource, &QPushButton::clicked, this, &MainWindow::chooseSource);
    connect(btnDest, &QPushButton::clicked, this, &MainWindow::chooseDestination);

    // Mode
    rbEncrypt = new QRadioButton(tr("Шифрование"));
    rbDecrypt = new QRadioButton(tr("Расшифрование"));
    rbEncrypt->setChecked(true);
    connect(rbEncrypt, &QRadioButton::toggled, this, &MainWindow::onModeChanged);

    // Password options
    rbPassKeyboard = new QRadioButton(tr("Пароль с клавиатуры"));
    rbPassFile = new QRadioButton(tr("Пароль из файла"));
    rbPassKeyboard->setChecked(true);
    connect(rbPassFile, &QRadioButton::toggled, this, &MainWindow::onModeChanged);

    lePassword = new QLineEdit;
    lePassword->setEchoMode(QLineEdit::Password);
    btnPassFile = new QPushButton(tr("Выбрать файл с паролем..."));
    connect(btnPassFile, &QPushButton::clicked, this, &MainWindow::choosePasswordFile);

    btnProcess = new QPushButton(tr("Выполнить"));
    connect(btnProcess, &QPushButton::clicked, this, &MainWindow::processFile);

    progress = new QProgressBar;
    progress->setMinimum(0);
    progress->setMaximum(100);
    progress->setValue(0);

    // Layouts
    QVBoxLayout *mainL = new QVBoxLayout;
    mainL->addWidget(lblStudent);
    mainL->addWidget(lblVariant);
    mainL->addWidget(txtAlgorithm);

    QHBoxLayout *srcL = new QHBoxLayout;
    srcL->addWidget(new QLabel(tr("Исходный:")));
    srcL->addWidget(leSource);
    srcL->addWidget(btnSource);
    mainL->addLayout(srcL);

    QHBoxLayout *dstL = new QHBoxLayout;
    dstL->addWidget(new QLabel(tr("Назначение:")));
    dstL->addWidget(leDest);
    dstL->addWidget(btnDest);
    mainL->addLayout(dstL);

    QHBoxLayout *modeL = new QHBoxLayout;
    modeL->addWidget(rbEncrypt);
    modeL->addWidget(rbDecrypt);
    mainL->addLayout(modeL);

    QGroupBox *gbPass = new QGroupBox(tr("Пароль"));
    QVBoxLayout *passL = new QVBoxLayout;
    QHBoxLayout *passOptions = new QHBoxLayout;
    passOptions->addWidget(rbPassKeyboard);
    passOptions->addWidget(rbPassFile);
    passL->addLayout(passOptions);
    QHBoxLayout *passInput = new QHBoxLayout;
    passInput->addWidget(new QLabel(tr("Пароль:")));
    passInput->addWidget(lePassword);
    passInput->addWidget(btnPassFile);
    passL->addLayout(passInput);
    gbPass->setLayout(passL);
    mainL->addWidget(gbPass);

    mainL->addWidget(btnProcess);
    mainL->addWidget(progress);

    w->setLayout(mainL);

    setWindowTitle(tr("DES-CBC — шифрование/расшифрование (Qt)"));
    resize(800, 600);

    onModeChanged();
}

void MainWindow::chooseSource()
{
    QString fn = QFileDialog::getOpenFileName(this, tr("Выберите исходный файл"));
    if (!fn.isEmpty()) {
        sourcePath = fn;
        leSource->setText(fn);
    }
}

void MainWindow::chooseDestination()
{
    QString fn = QFileDialog::getSaveFileName(this, tr("Выберите файл назначения"));
    if (!fn.isEmpty()) {
        destPath = fn;
        leDest->setText(fn);
    }
}

void MainWindow::choosePasswordFile()
{
    QString fn = QFileDialog::getOpenFileName(this, tr("Выберите файл с паролем"));
    if (!fn.isEmpty()) {
        passFilePath = fn;
        // выводим путь в lePassword (не раскрываем содержимое)
        lePassword->setText("[файл] " + QFileInfo(fn).fileName());
    }
}

void MainWindow::onModeChanged()
{
    bool passFile = rbPassFile->isChecked();
    lePassword->setEnabled(!passFile);
    btnPassFile->setEnabled(passFile);
    if (rbEncrypt->isChecked()) {
        btnProcess->setText(tr("Шифровать"));
    } else {
        btnProcess->setText(tr("Расшифровать"));
    }
}

QByteArray MainWindow::deriveKeyFromPassword(const QByteArray& pass) {
    QByteArray md = QCryptographicHash::hash(pass, QCryptographicHash::Md5);
    return md.left(8); // 8 байт -> DES
}

bool MainWindow::readPassword(std::vector<uint8_t>& out)
{
    QByteArray keybytes;
    if (rbPassFile->isChecked()) {
        if (passFilePath.isEmpty()) {
            QMessageBox::warning(this, tr("Ошибка"), tr("Файл с паролем не выбран"));
            return false;
        }
        QFile pf(passFilePath);
        if (!pf.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, tr("Ошибка"), tr("Не удалось открыть файл с паролем"));
            return false;
        }
        QByteArray content = pf.readAll().trimmed();
        pf.close();
        if (content.isEmpty()) {
            QMessageBox::warning(this, tr("Ошибка"), tr("Файл с паролем пуст"));
            return false;
        }
        keybytes = deriveKeyFromPassword(content);
    } else {
        QString p = lePassword->text();
        if (p.isEmpty()) {
            QMessageBox::warning(this, tr("Ошибка"), tr("Пароль не введён"));
            return false;
        }
        keybytes = deriveKeyFromPassword(p.toUtf8());
    }
    out.resize(8);
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)keybytes.at(i);
    return true;
}

bool MainWindow::encryptStream(QFile &inFile, QFile &outFile, const std::array<uint8_t,8>& key)
{
    // генерируем IV
    std::array<uint8_t,8> iv;
    for (int i=0;i<8;++i) iv[i] = (uint8_t)QRandomGenerator::global()->bounded(0,256);

    // записываем IV в начало выходного файла
    if (outFile.write(reinterpret_cast<const char*>(iv.data()), 8) != 8) return false;

    DES des;
    des.setKey(key);

    const int block = 8;
    QByteArray buffer;
    buffer.resize(block);

    qint64 total = inFile.size();
    qint64 processed = 0;
    progress->setValue(0);

    // CBC: prev = IV
    std::array<uint8_t,8> prev = iv;

    // читаем блоками
    while (!inFile.atEnd()) {
        qint64 toRead = qMin<qint64>(block, inFile.size() - inFile.pos());
        QByteArray chunk = inFile.read(toRead);
        if (chunk.size() < block) {
            // pad PKCS#7
            int pad = block - chunk.size();
            chunk.append(QByteArray(pad, (char)pad));
        }
        // если chunk size == 8, можем обработать прямо
        uint8_t inb[8];
        memcpy(inb, chunk.constData(), 8);
        // XOR with prev
        for (int i=0;i<8;++i) inb[i] ^= prev[i];
        uint8_t outb[8];
        des.encryptBlock(inb, outb);
        if (outFile.write(reinterpret_cast<const char*>(outb), 8) != 8) return false;
        // prev = outb
        for (int i=0;i<8;++i) prev[i] = outb[i];

        processed += toRead;
        int perc = int((processed*100)/total);
        progress->setValue(qMin(perc, 99)); // финал будет 100 в конце
    }
    progress->setValue(100);
    return true;
}

bool MainWindow::decryptStream(QFile &inFile, QFile &outFile, const std::array<uint8_t,8>& key)
{
    // читаем IV из начала
    uint8_t iv[8];
    if (inFile.read(reinterpret_cast<char*>(iv), 8) != 8) return false;

    DES des;
    des.setKey(key);

    const int block = 8;
    qint64 total = inFile.size(); // уже после чтения 8 байт
    qint64 processed = 0;
    progress->setValue(0);

    std::array<uint8_t,8> prev;
    for (int i=0;i<8;++i) prev[i] = iv[i];

    // Для корректного удаления паддинга нужно знать последний блок — будем читать блок впереди (CBC streaming)
    QByteArray cur = inFile.read(block);
    if (cur.size() == 0) return false;

    while (true) {
        QByteArray next = inFile.read(block);
        // decrypt cur
        uint8_t cur_in[8];
        if (cur.size() < 8) return false; // не кратно 8 -> ошибка
        memcpy(cur_in, cur.constData(), 8);
        uint8_t dec[8];
        des.decryptBlock(cur_in, dec);
        // XOR with prev
        for (int i=0;i<8;++i) dec[i] ^= prev[i];

        if (next.size() == 0) {
            // последний блок -> убрать padding
            int pad = dec[7]; // значение заполнителя
            if (pad < 1 || pad > 8) {
                QMessageBox::warning(this, tr("Ошибка"), tr("Неверный padding — возможно, неверный пароль или повреждён файл."));
                return false;
            }
            // проверяем паддинг
            for (int i=8-pad;i<8;++i) {
                if ((uint8_t)dec[i] != pad) {
                    QMessageBox::warning(this, tr("Ошибка"), tr("Неверный padding — возможно, неверный пароль или повреждён файл."));
                    return false;
                }
            }
            if (outFile.write(reinterpret_cast<const char*>(dec), 8 - pad) != (8 - pad)) return false;
            processed += block;
            progress->setValue(100);
            break;
        } else {
            if (outFile.write(reinterpret_cast<const char*>(dec), 8) != 8) return false;
            processed += block;
            int perc = int((processed*100)/total);
            progress->setValue(qMin(perc, 99));
            // shift
            for (int i=0;i<8;++i) prev[i] = (uint8_t)cur_in[i];
            cur = next;
        }
    }
    return true;
}

void MainWindow::processFile()
{
    if (leSource->text().isEmpty() || leDest->text().isEmpty()) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Выберите исходный и файл назначения."));
        return;
    }
    QFile inFile(sourcePath);
    if (!inFile.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Не удалось открыть исходный файл."));
        return;
    }
    QFileInfo fi(inFile);
    if (fi.size() < 1024) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Размер исходного файла должен быть не менее 1 КБ."));
        inFile.close();
        return;
    }

    QFile outFile(destPath);
    if (!outFile.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Не удалось открыть файл назначения для записи."));
        inFile.close();
        return;
    }

    std::vector<uint8_t> keyv;
    if (!readPassword(keyv)) {
        inFile.close();
        outFile.close();
        return;
    }
    std::array<uint8_t,8> key;
    for (int i=0;i<8;++i) key[i] = keyv[i];

    bool ok = false;
    if (rbEncrypt->isChecked()) {
        ok = encryptStream(inFile, outFile, key);
    } else {
        ok = decryptStream(inFile, outFile, key);
    }

    inFile.close();
    outFile.close();

    if (ok) {
        QMessageBox::information(this, tr("Готово"), tr("Операция завершена успешно."));
    } else {
        QMessageBox::warning(this, tr("Ошибка"), tr("Во время операции произошла ошибка."));
    }
    progress->setValue(100);
}
