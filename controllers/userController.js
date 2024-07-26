// UserModelとbcrypt、jwtをインポート
import UserModel from '../models/User.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// UserControllerクラスを定義
class UserController {
  // 静的メソッドuserRegistrationを定義
  static userRegistration = async (req, res) => {
    // リクエストボディから必要な情報を取得
    const { name, email, password, password_confirmation, tc } = req.body;
    // 指定されたメールアドレスを持つユーザーを検索
    const user = await UserModel.findOne({ email: email });
    // ユーザーが存在する場合、エラーメッセージを返す
    if (user) {
      return res.send({
        status: 'failed',
        message: 'Emailはすでに使われています',
      });
    }
    // 必須フィールドのいずれかが欠けている場合、エラーメッセージを返す
    if (!(name && email && password && password_confirmation && tc)) {
      return res.send({
        status: 'failed',
        message: 'すべての項目を入力してください',
      });
    }

    // パスワードと確認用パスワードが一致する場合
    if (password === password_confirmation) {
      try {
        // パスワードをハッシュ化
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);
        // 新しいユーザードキュメントを作成
        const doc = new UserModel({
          name: name,
          email: email,
          password: hashPassword,
          tc: tc,
        });
        // ユーザードキュメントを保存
        await doc.save();
        // 保存されたユーザーを検索
        const saved_user = await UserModel.findOne({ email: email });
        // JWTトークンを生成
        const token = jwt.sign(
          { userID: saved_user._id },
          process.env.JWT_SECRET_KEY,
          { expiresIn: '5d' }
        );
        // 成功レスポンスを送信
        res.status(201).send({
          status: 'success',
          message: 'Registration Success',
          token: token,
        });
      } catch (error) {
        // エラーをコンソールに出力
        console.log(error);
        // 登録失敗のレスポンスを送信
        res.send({ status: 'failed', message: '登録に失敗しました' });
      }
    } else {
      // パスワードと確認用パスワードが一致しない場合、エラーメッセージを返す
      res.send({
        status: 'failed',
        message: 'パスワードと確認用パスワードが一致しません',
      });
    }
  };
}

export default UserController;
