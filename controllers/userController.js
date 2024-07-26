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
        // 保存されたユーザーを検索(保存されたユーザーのIDをtokenに使用するため)
        const saved_user = await UserModel.findOne({ email: email });
        // JWTトークンを生成
        const token = jwt.sign(
          { userID: saved_user._id },
          process.env.JWT_SECRET_KEY,
          { expiresIn: '1h' }
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

  static userLogin = async (req, res) => {
    try {
      // リクエストボディからemailとpasswordを取得
      const { email, password } = req.body;

      // emailまたはpasswordが存在しない場合、エラーレスポンスを返す
      if (!email || !password) {
        return res.send({
          status: 'failed',
          message: '全てのフィールドが必須です',
        });
      }

      // データベースからemailが一致するユーザーを検索
      const user = await UserModel.findOne({ email: email });

      // ユーザーが存在しない場合、エラーレスポンスを返す
      if (user === null) {
        return res.send({
          status: 'failed',
          message: '登録されていないユーザーです',
        });
      }

      // パスワードの一致を検証
      const isMatch = await bcrypt.compare(password, user.password);

      // emailまたはパスワードが一致しない場合、エラーレスポンスを返す
      if (user.email !== email || !isMatch) {
        return res.send({
          status: 'failed',
          message: 'メールアドレスまたはパスワードが無効です',
        });
      }

      // JWTトークンを生成
      const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET_KEY, {
        expiresIn: '1h',
      });

      // ログイン成功のレスポンスを送信
      return res.send({
        status: 'success',
        message: 'ログイン成功',
        token: token,
      });
    } catch (error) {
      // エラーをコンソールに出力
      console.log(error);
      // ログインできない場合のレスポンスを送信
      return res.send({ status: 'failed', message: 'ログインできません' });
    }
  };

  static changeUserPassword = async (req, res) => {
    // リクエストボディからpasswordとpassword_confirmationを取得
    const { password, password_confirmation } = req.body;

    // passwordまたはpassword_confirmationが存在しない場合、エラーレスポンスを返す
    if (!password || !password_confirmation) {
      return res.send({
        status: 'failed',
        message: '全てのフィールドが必須です',
      });
    }

    // passwordとpassword_confirmationが一致しない場合、エラーレスポンスを返す
    if (password !== password_confirmation) {
      return res.send({
        status: 'failed',
        message: '新しいパスワードと確認用パスワードが一致しません',
      });
    }

    try {
      // bcryptを使用して新しいパスワードをハッシュ化
      const salt = await bcrypt.genSalt(10);
      const newHashPassword = await bcrypt.hash(password, salt);

      // ユーザーのパスワードを更新
      await UserModel.findByIdAndUpdate(req.user._id, {
        $set: { password: newHashPassword },
      });

      // 成功レスポンスを返す
      return res.send({
        status: 'success',
        message: 'パスワードが正常に変更されました',
      });
    } catch (error) {
      // エラーが発生した場合、エラーレスポンスを返す
      console.log(error);
      return res.send({
        status: 'failed',
        message: 'パスワードの変更に失敗しました',
      });
    }
  };
}

export default UserController;
