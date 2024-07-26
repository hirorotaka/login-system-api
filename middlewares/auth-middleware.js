// jsonwebtokenとUserModelをインポート
import jwt from 'jsonwebtoken';
import UserModel from '../models/User.js';

// ユーザー認証のミドルウェア関数を定義
const checkUserAuth = async (req, res, next) => {
  // トークン変数を宣言
  let token;
  // リクエストヘッダーからauthorizationを取得
  const { authorization } = req.headers;
  // authorizationが存在し、'Bearer'で始まる場合
  if (authorization && authorization.startsWith('Bearer')) {
    try {
      // authorizationからトークンを取得
      token = authorization.split(' ')[1];

      // トークンを検証
      const { userID } = jwt.verify(token, process.env.JWT_SECRET_KEY);

      // トークンからユーザー情報を取得し、パスワードを除外
      req.user = await UserModel.findById(userID).select('-password');

      // 次のミドルウェアまたはルートハンドラーに進む
      next();
    } catch (error) {
      // エラーが発生した場合、エラーをコンソールに出力
      console.log(error);
      // 401 Unauthorizedステータスとエラーメッセージを送信
      res
        .status(401)
        .send({ status: '失敗', message: '認証されていないユーザー' });
    }
  }
  // トークンが存在しない場合
  if (!token) {
    // 401 Unauthorizedステータスとエラーメッセージを送信
    res
      .status(401)
      .send({
        status: '失敗',
        message: '認証されていないユーザー、トークンがありません',
      });
  }
};

// ミドルウェア関数をデフォルトエクスポート
export default checkUserAuth;
