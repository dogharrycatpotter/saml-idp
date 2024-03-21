
/**
 * User Profile
 */
var profile = {
  userName: 'saml.jackson@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  // firstName: 'Saml',
  // lastName: 'Jackson',
  // email: 'saml.jackson@example.com',
  // displayName: 'saml jackson',
  // mobilePhone: '+1-415-555-5141',
  // groups: 'Simple IdP Users, West Coast Users, Cloud Users',
  appUserId1: '',
  // appUserId2: '',
  // loginDate: '',
}

/**
 * SAML Attribute Metadata
 */
var metadata = [
// {
//   id: "firstName",
//   optional: false,
//   displayName: 'First Name',
//   description: 'The given name of the user',
//   multiValue: false
// },
// {
//   id: "lastName",
//   optional: false,
//   displayName: 'Last Name',
//   description: 'The surname of the user',
//   multiValue: false
// },
// {
//   id: "email",
//   optional: false,
//   displayName: 'E-Mail Address',
//   description: 'The e-mail address of the user',
//   multiValue: false
// },
// {
//   id: "displayName",
//   optional: true,
//   displayName: 'Display Name',
//   description: 'The display name of the user',
//   multiValue: false
// },
// {
//   id: "mobilePhone",
//   optional: true,
//   displayName: 'Mobile Phone',
//   description: 'The mobile phone of the user',
//   multiValue: false
// },
// {
//   id: "groups",
//   optional: true,
//   displayName: 'Groups',
//   description: 'Group memberships of the user',
//   multiValue: true
// },
// {
//   id: "userType",
//   optional: true,
//   displayName: 'User Type',
//   description: 'The type of user',
//   options: ['Admin', 'Editor', 'Commenter']
// },
{
  id: "appUserId1",
  optional: true,
  displayName: 'Application User Id 1',
  description: 'SP Application User Id 1',
  multiValue: false
},
// {
//   id: "appUserId2",
//   optional: true,
//   displayName: 'Application User Id 2',
//   description: 'SP Application User Id 2',
//   multiValue: false
// },
// {
//   id: "loginDate",
//   optional: true,
//   displayName: 'Login Date',
//   description: 'Login Date',
//   multiValue: false
// }
{
  id: "statusCode",
  optional: true,
  displayName: 'StatusCode of Response',
  description: 'StatusCode of Response',
  options: [
    // 要求は成功しました。追加情報は <StatusMessage> および/または <StatusDetail> 要素に返される場合があります。
    'Success',
    // 要求者のエラーにより、要求を実行できませんでした。
    'Requester',
    // SAML レスポンダまたは SAML 機関のエラーにより、要求を実行できませんでした。
    'Responder',
    // 要求メッセージのバージョンが正しくないため、SAML レスポンダが要求を処理できませんでした。
    'VersionMismatch'
  ]
},
{
  id: "nestedStatusCode",
  optional: true,
  displayName: 'Nested StatusCode of Response',
  description: 'Nested StatusCode of Response',
  options: [
    '',
    // 応答プロバイダはプリンシパルの認証に成功しませんでした。
    'AuthnFailed',
    // <saml:Attribute> または <saml:AttributeValue> 要素内で予期しないか無効なコンテンツが遭遇されました。
    'InvalidAttrNameOrValue',
    // 応答プロバイダは要求された名前識別子ポリシーをサポートできないか、サポートしません。
    'InvalidNameIDPolicy',
    // 応答プロバイダは、指定された認証コンテキスト要件を満たすことができません。
    'NoAuthnContext',
    // 中間者が示す通り、<IDPList> 内のサポートされる ID プロバイダ <Loc> 要素のいずれも解決されないか、サポートされていない場合。
    'NoAvailableIDP',
    // 応答プロバイダは要求されたようにプリンシパルを受動的に認証できません。
    'NoPassive',
    // 中間者が示す通り、<IDPList> 内の ID プロバイダのいずれも中間者によってサポートされていない場合。
    'NoSupportedIDP',
    // セッション権限者が、ログアウトを他のすべてのセッション参加者に伝達できなかったことをセッション参加者に示すために使用されます。
    'PartialLogout',
    // 応答プロバイダがプリンシパルを直接認証できず、さらにリクエストをプロキシできないことを示します。
    'ProxyCountExceeded',
    // SAML レスポンダまたは SAML 権限者がリクエストを処理できるが、応答しないことを選択しました。このステータスコードは、特定の要求者から受信した要求メッセージまたは要求メッセージのシーケンスのセキュリティコンテキストに関する懸念がある場合に使用される場合があります。
    'RequestDenied',
    // SAML レスポンダまたは SAML 権限者がリクエストをサポートしていません。
    'RequestUnsupported',
    // SAML レスポンダは、リクエストで指定されたプロトコルバージョンを処理できません。
    'RequestVersionDeprecated',
    // SAML レスポンダは、要求メッセージで指定されたプロトコルバージョンが、レスポンダがサポートする最高プロトコルバージョンよりも大幅に上昇しているため、要求を処理できません。
    'RequestVersionTooHigh',
    // SAML レスポンダは、要求メッセージで指定されたプロトコルバージョンが低すぎるため、要求を処理できません。
    'RequestVersionTooLow',
    // リクエストメッセージで提供されたリソース値が無効または認識されないものであることを示します。
    'ResourceNotRecognized',
    // 応答メッセージに含まれる要素が、SAML レスポンダが返すことができる要素よりも多いことを示します。
    'TooManyResponses',
    // 特定の属性プロファイルに関する知識がないエンティティが、そのプロファイルからの属性を提示されたことを示します。
    'UnknownAttrProfile',
    // 応答プロバイダが、要求で指定されたまたは暗示されたプリンシパルを認識していません。
    'UnknownPrincipal',
    // SAML レスポンダは、要求内で指定されたプロトコルバインディングを使用して要求を適切に処理できません。
    'UnsupportedBinding'
  ]
},
{
  id: "statusMessage",
  optional: true,
  displayName: 'StatusMessage of Response',
  description: 'StatusMessage of Response',
  multiValue: false
},
{
  id: "statusDetail",
  optional: true,
  displayName: 'StatusDetail of Response',
  description: 'StatusDetail of Response',
  multiValue: false
}
];

module.exports = {
  user: profile,
  metadata: metadata
}
