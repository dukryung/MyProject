$(document).ready(function () {
	//validate 와 val() 값을 동시에 사용하기때문에 selector 의 속도및 자원사용을 줄이기 위한 변수선언;
	//만약 이후 selector 의 이름이 변경 될 경우 아래 selector 의 id 만 변경해 줘도 무방함
	
  
  function SetupAuthRequest ( id, password , ordernum) {
    
    id = $.trim(id)
    password = $.trim(password)
    ordernum = $.trim(ordernum)
    
    if (id == "") {
      alert ("유효하지 않은 id 입니다.");
      return 
    }
    
    if (password == "") {
      alert ("유효하지 않은 password 입니다.");
      return 
    }

    if (ordernum == "") {
      alert ("유효하지 않은 ordernum 입니다.");
      return 
    } 

    var send_json_data = {
                          "login_id"                  : id,
                          "password"                  : password,
                          "order_num"                 : ordernum,
                          };
    $.ajax({
        async: false,
        url: /*url +*/ "/logging_svc/",
        timeout:5000,
        type: "POST",
        dataType: "json",
        contentType: 'application/json; charset=UTF-8',
        data: JSON.stringify(send_json_data),
        complete: 
          function (response, textStatus) {
            var jsonObject = JSON.parse(response.responseText);

            if (response.status == "200") {
              if (jsonObject.code == "200") {
                alert("Service 인증 성공")
                alert("1분 후, 브라우저를 새로고침해주세요")
              } else {
                if (jsonObject.code == "655") {
                  alert("가입하지 않은 아이디이거나, 유효하지 않은 비밀번호 또는 상품번호 입니다.")
                } else {
                  alert("Service 인증 실패")
                }
              }
            } else {
              alert("오류발생\n(Network 상태를 확인하여 주시기 바랍니다.)");
            }
          },
        error: 
          function(xml_request, text_status, error_thrown) {
            alert("오류발생\n(Network 상태를 확인하여 주시기 바랍니다.)");
          },
    });

    return 
  }

	//페이지가 준비가 완료 되면 Frontend 의 이벤트를 걸어준다
	$('#wrapper button[act]').on('click', function (e) {
		e.preventDefault();
		var act = $(this).attr('act');
	
      if (act == "btnsvc") {
        AuthSVC();             
      } else if (act == "btnsvccancel") {
        AuthSVCCancel();
      }
    });

    function AuthSVCCancel() {
      history.back()
     
    }

function AuthSVC() {

    var id = $("#id").val();
    var password = $("#pwd").val();
    var ordernum = $("#ordernum").val();

    SetupAuthRequest(id, password, ordernum)
}

	//frontend 를 바인딩

});

