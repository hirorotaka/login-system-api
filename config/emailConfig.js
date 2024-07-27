import dotenv from 'dotenv';
dotenv.config();
import nodemailer from 'nodemailer';

// nodemailerのトランスポーターを作成
// これはSMTPサーバーへの接続設定を定義し、メール送信の基盤となる
let transporter = nodemailer.createTransport({
  // SMTPサーバーのホスト名
  // 例: 'smtp.gmail.com'（Gmailの場合）や 'smtp.office365.com'（Office 365の場合）
  host: process.env.EMAIL_HOST,

  // SMTPサーバーのポート番号
  // 一般的には、非暗号化接続には25、SSL/TLSには465、STARTTLS接続には587を使用
  port: process.env.EMAIL_PORT,

  // セキュアな接続（SSL/TLS）を使用するかどうか
  // false: STARTTLS（ポート587）を使用する場合
  // true: SSL/TLS（通常ポート465）を使用する場合
  secure: false,

  // SMTP認証の設定
  auth: {
    // SMTPサーバーのユーザー名（通常はメールアドレス）
    // 多くの場合、送信元のメールアドレスと同じ
    user: process.env.EMAIL_USER,

    // SMTPサーバーのパスワードまたはアプリパスワード
    // セキュリティのため、環境変数から読み込む
    // Gmailの場合、2段階認証を有効にしてアプリパスワードを使用することを推奨
    pass: process.env.EMAIL_PASSWORD,
  },

  // TLSの設定（オプション）
  // tls: {
  //   // 自己署名証明書を使用する場合にtrueに設定
  //   // rejectUnauthorized: false
  // }
});

// トランスポーターをエクスポート
// これにより、アプリケーションの他の部分でこの設定を使用してメールを送信できる
export default transporter;
