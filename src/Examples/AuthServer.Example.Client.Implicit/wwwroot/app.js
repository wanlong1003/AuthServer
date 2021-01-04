//添加事件
document.getElementById("login").addEventListener("click", login, false);
document.getElementById("api").addEventListener("click", api, false);
document.getElementById("logout").addEventListener("click", logout, false);

//配置
var config = {
    authority: "https://localhost:5000",
    client_id: "implicit_client",
    redirect_uri: "https://localhost:5003/callback.html",
    response_type: "id_token token",  //同时返回id_token和token
    scope: "openid api1",
    post_logout_redirect_uri: "https://localhost:5003/index.html",
};

var mgr = new Oidc.UserManager(config);

mgr.getUser().then(function (user) {
    if (user) {
        console.log(user)
    }
    else {
        console.log("User not logged in");
    }
});

//登录
function login() {
    mgr.signinRedirect();
}

//调用api
function api() {
    mgr.getUser().then(function (user) {
        var url = "http://localhost:5001/api/identity";
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url);
        xhr.onload = function () {
            log(xhr.status, JSON.parse(xhr.responseText));
        }
        xhr.setRequestHeader("Authorization", "Bearer " + user.access_token);
        xhr.send();
    });
}

//退出登录
function logout() {
    mgr.signoutRedirect();
}