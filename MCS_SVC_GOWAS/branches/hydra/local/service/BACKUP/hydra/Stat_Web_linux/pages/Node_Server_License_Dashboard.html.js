$(document).ready(function () {
    var $LicenseData = $('#licensedata');
    
    
    function TransValue() {
        var params = {
          "Licensedata" : $LicenseData.val()
        };
            target_url = "license"

        $.ajax({
			url: target_url,
			type: 'POST',
			accepts: { mycustomtype: 'application/x-some-custom-type' },
			data: JSON.stringify(params),
			success: function () {
				alert("저장 완료");
                location.reload();
			},
			error: function () {
				alert("저장 실패");
			}
		});

    };

    $('main button[act]').on('click',function(e){
        e.preventDefault();
        if (act == "btnSave"){
            TransValue();
        }
    });
});
