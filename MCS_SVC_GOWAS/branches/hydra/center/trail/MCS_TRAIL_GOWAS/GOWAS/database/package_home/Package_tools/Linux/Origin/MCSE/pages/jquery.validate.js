(function ($) {
	// 유효성 검사 확장 함수
	$.extend($.fn, {
		oShow: $.fn.show,
		oHide: $.fn.hide,
		oRemove: $.fn.remove,
		// 해당 개체에 유효성 검사 추가(이미 추가된 경우 기존 유효성 검사 개체에 옵션만 적용한다.)
		validate: function (options) {
			this.each(function (i, e) {
				var $e = $(e);

				if (!$e.is(':visible'))
					return this;

				if (typeof ($e.prop('validate')) == 'undefined') {
					$.validator.tooltipObject(e, options);
				}
				else {
					var typename = $e.prop('type').toLowerCase(),
						box = e._contract.box;
					if (typename == 'checkbox') {
						box.addClass('validate_checkbox').show();
						$e.hide();
					}

					$e.prop('validate', true);
					$.validator.setOption(e, options);
				}
			});

			return this;
		},
		// 개체의 옵션변경
		option: function (oName, oValue) {
			this.each(function (i, e) {
				var $e = $(e);

				if (!$e.is(':visible'))
					return this;

				if (typeof ($e.prop('validate')) != 'undefined') {
					if (typeof (oName) == 'string') {
						e._contract.options[oName] = oValue;
						if (oName.toLowerCase() == 'reserve') {
							$.validator.setOption(e);
						}
					}
				}
			});

			return this;
		},
		// 개체의 강제 메세지 출력
		validateAlert: function (alertMsg) {
			this.each(function (i, e) {
				var $e = $(e);

				if (!$e.is(':visible'))
					return this;

				if (typeof ($e.prop('validate')) != 'undefined' && $e.prop('validate')) {
					$e.trigger('alert', [alertMsg]);
				}
			});

			return this;
		},
		// 개체의 유효성체크 메세지 닫기
		validateClose: function (callbackClose) {
			this.each(function (i, e) {
				var $e = $(e);

				if (!$e.is(':visible'))
					return this;

				if (typeof ($e.prop('validate')) != 'undefined' && $e.prop('validate')) {
					var box = e._contract.box,
						options = e._contract.options;
					box.slideUp(options.speed, function () {
						$(this).prop('validate_view', false);
						if (callbackClose) {
							callbackClose();
						}
					});
				}
				else
					callbackClose();
			});

			return this;
		},
		// 개체의 유효성 검사 제거
		validateRemove: function () {
			this.each(function (i, e) {
				var $e = $(e);

				if (typeof ($e.prop('validate')) != 'undefined' && $e.prop('validate')) {
					var typename = $e.prop('type').toLowerCase(),
						box = e._contract.box,
						options = e._contract.options;

					if (typename == 'checkbox') {
						box.removeClass('validate_checkbox').hide();
						$e.show();
					}
					else {
						$e.removeClass('validated').removeClass('invalidate');
						box.slideUp(Number(options.speed), function () {
							box.find('.validate_message').html('');
							$(this).prop('validate_view', false);
						});
					}
					$e.prop('validate', false);
				}
			});

			return this;
		},
		// jQuery show 함수 재정의
		show: function () {
			this.each(function (i, e) {
				var $e = $(e);
				if (typeof ($e.prop('validate')) != 'undefined') {
					var typename = $e.prop('type').toLowerCase();
					if (typename == 'checkbox')
						$e.prev().oShow();
					else
						$e.parent().oShow();
				}
				else
					$e.oShow();
			});

			return this;
		},
		// jQuery hide 함수 재정의
		hide: function () {
			this.each(function (i, e) {
				var $e = $(e);
				if (typeof ($e.prop('validate')) != 'undefined') {
					var typename = $e.prop('type').toLowerCase();
					if (typename == 'checkbox') {
						$e.prev().oHide();
					}
					else
						$e.parent().oHide();
				}
				else
					$e.oHide();
			});

			return this;
		},
		// jQuery remove 함수 재정의
		remove: function () {
			this.each(function (i, e) {
				var $e = $(e);
				if (typeof ($e.prop('validate')) != 'undefined') {
					var typename = $e.prop('type').toLowerCase();
					if (typename == 'checkbox') {
						$e.prev().oHide();
						$e.oRemove();
					}
					else
						$e.parent().oRemove();
				}
				else
					$e.oRemove();
			});

			return this;
		}
	}),
	// 유효성 검사 플러그인
$.validator = {
	// 정규식 예약어(일반)
	genRegex: function (options) {
		var reserves = new Array(),
			regexp = '',
			regexpExt = '',
			reserveStr = options.reserve,
			minStr = options.min,
			maxStr = options.max,
			reglen = '';
		reserves = reserveStr.split(' ');

		// 정규식 길이
		if (!minStr && !maxStr) {
			reglen = '*';
		}
		else {
			minStr = minStr ? minStr : '0';
			maxStr = maxStr ? maxStr : '';
			reglen = '{' + minStr + ',' + maxStr + '}';
		}

		// 예약
		// ko				: 한글
		// en				: 영어
		// zh				: 한자
		// ja				: 일본어
		// number		: 숫자
		// space		: 공백
		// specail	: 특수문자
		// domain		: 도메인
		// domain80	: 도메인(80자 제한)
		$.each(reserves, function (i, reserve) {
			switch (reserve) {
				case 'ko':
					regexp += '|\\u1100-\\u11FF\\u3130-\\u318F\\uAC00-\\uD7AF';
					break;
				case 'en':
					regexp += '|\\u0061-\\u007A\\u0041-\\u005A';
					break;
				case 'zh':
					regexp += '|\\u4E00-\\u62FF\\u6300-\\u77FF\\u7800-\\u8CFF\\u8D00-\\u9FFF\\u3400-\\u4DBF\\u2E80-\\u2EFF\\u2F00-\\u2FDF\\u2FF0-\\u2FFF\\u3000-\\u303F\\u31C0-\\u31EF\\u3200-\\u32FF\\u3300-\\u33FF\\uF900-\\uFAFF\\uFE30-\\uFE4F';
				case 'ja':
					regexp += '|\\u4E00-\\u62FF\\u6300-\\u77FF\\u7800-\\u8CFF\\u8D00-\\u9FFF\\u3400-\\u4DBF\\u2E80-\\u2EFF\\u2F00-\\u2FDF\\u2FF0-\\u2FFF\\u3000-\\u303F\\u31C0-\\u31EF\\u3200-\\u32FF\\u3300-\\u33FF\\uF900-\\uFAFF\\uFE30-\\uFE4F\\u3040-\\u309F\\u30A0-\\u30FF\\u31F0-\\u31FF';
					break;
				case 'number':
					regexp += '|\\u0030-\\u0039';
					break;
				case 'space':
					regexp += '|\\s';
					break;
				case 'special':
					regexp += '|\\,\\.\\/\\-\\&';
					break;
				case 'special_extra':
					regexp += '|\\~\\!\\@\\#\\$\\%\\^\\&\\*\\(\\)\\_\\+\\|\\`\\-\\=\\\\\[\\]\\;\\\'\\,\\.\\/\\{\\}\\:\\"\\<\\>\\?';
					break;
				case 'email_extra':
					regexp += '|\\-\\_\\.\\@';
					break;
				case 'n/a':
					regexpExt += '|(n\\/a)';
					break;
				case 'hyphen':
					regexp += '|\\-';
					break;
				case 'fullstop':
					regexp += '|\\.';
					break;
				case 'length':
				case 'email':
				case 'url':
				case 'domain_lable':
				case 'domain_notld':
				case 'domain_name':
				case 'domain80':
				case 'host':
				case 'host_wildcard':
				case 'host_ptr':
				case 'ipv4':
				case 'ipv4_bandwidth':
				case 'ipv6':
				case 'ipv4_ipv6':
                case 'uuid':
				case 'record_a':
				case 'record_aaaa':
				case 'record_ptr':
				case 'record_cname':
				case 'record_mx':
				case 'record_ns':
				case 'password':
				case 'between':
				case 'creditcard':
					options.special = reserve;
					return false;
					break;
				default:
					regexp += '|';
					break;
			}
		});

		// 정규식 생성
		regexp = '^(?:([' + regexp.substr(1, regexp.length) + ']' + reglen + ')' + regexpExt + ')$';
		return regexp;
	},
	// 정규식 검사. 특별한 경우 별도로 만들어준다.
	regEx: function (special, regex, minStr, maxStr, modifiers, value) {
		var resultValidate = false,
			defaultMaxStr = maxStr && maxStr != '' ? Number(maxStr) : 255,
      en = 'a-z', // 기본 영문자
			number = '\\u0030-\\u0039',
			regexpEnWithNum = new RegExp('^[' + number + en + ']{1}[' + number + en + '-]{0,61}[' + number + en + ']{1}$', 'i'), // 도메인 영문, 숫자시작, 하이픈 체크(총길이 63)
			regexpEnWithNumNoHypen = new RegExp('^[' + number + en + ']{2,63}$', 'i'), // 도메인 영문, 숫자시작 체크(총길이 63)
			regexpHost = new RegExp('^[' + number + en + '-]{1,245}$', 'i'), // 호스트 영문, 숫자시작, 하이픈 체크(총길이 245)
			regexpTld = new RegExp('^([a-z]{2,63}|한국)$', 'i'), // 도메인 tld 체크
			wildcard = new RegExp('^\\*$'), // 와일드카드
			at = new RegExp('^\\@$'); // 골뱅이

		// 정규식 길이
		if (!minStr && !maxStr)
			reglen = '*';
		else {
			minStr = minStr ? minStr : '0';
			maxStr = maxStr ? maxStr : '';
			reglen = '{' + minStr + ',' + maxStr + '}';
		}

		switch (special) {
			case 'None':
				resultValidate = RegExp(regex, modifiers).test(value);
				break;
			case 'length':
				resultValidate = RegExp('^[\\s\\S\\n]' + reglen + '$', modifiers).test(value);
				break;
			case 'email':
				var regexpEmail = new RegExp('^[a-z0-9\\.\\-_]+@[a-z0-9.-]+\\.[a-z]{2,4}$', 'i');
				resultValidate = regexpEmail.test(value);
				break;
			case 'url':
				var regexpUrl = new RegExp('^(www\\.)?[a-zA-Z0-9-_]+(\\.[a-zA-Z0-9]{2,}){1,2}(\\.?(:[0-9]{0,5})?)?([\\/?]([-a-zA-Z0-9:%_\\+#?&=]+[-a-zA-Z0-9:%_\\+#?&=\\.]?)*)*$', 'i');
				resultValidate = regexpUrl.test(value);
				break;
			case 'domain_lable':
				if (typeof (value) === 'string') {
					var asciiStr = page.ascii(value);
					if (regexpEnWithNum.test(asciiStr) || regexpEnWithNumNoHypen.test(asciiStr))
						resultValidate = true;
					else {
						resultValidate = false;
						break;
					}
				}
				break;
			case 'domain_notld':
				if (typeof (value) === 'string') {
					var partArray = value.split('.'),
						partArrayLength = partArray.length;
					if (value.length <= defaultMaxStr) {
						for (var i = 0; i < partArrayLength; i++) {
							if (this.regEx('domain_lable', null, null, null, null, partArray[i]))
								resultValidate = true;
							else {
								resultValidate = false;
								break;
							}
						}
					}
				}
				break;
			case 'domain_name':
				if (typeof (value) === 'string') {
					var partArray = value.split('.'),
						partArrayLength = partArray.length;
					if (value.length <= defaultMaxStr && partArrayLength > 1) {
						for (var i = 0; i < partArrayLength; i++) {
							if (i == (partArrayLength - 1)) {
								if (!regexpTld.test(partArray[i])) {
									resultValidate = false;
									break;
								}
							}
							else
								if (this.regEx('domain_lable', null, null, null, null, partArray[i]))
									resultValidate = true;
								else {
									resultValidate = false;
									break;
								}
						}
					}
				}
				break;
			case 'domain80':
				if (typeof (value) === 'string') {
					var partArray = value.split('.'),
						partArrayLength = partArray.length;
					if (partArrayLength > 1)
						resultValidate = this.regEx('domain_name', null, null, '80', null, value);
				}
				break;
			case 'host':
				var asciiStr = page.ascii(value);

				if (at.test(value) || regexpHost.test(asciiStr))
					resultValidate = true;
				else
					resultValidate = this.regEx('domain_notld', null, null, null, null, value);
				break;
			case 'host_wildcard':
				var asciiStr = page.ascii(value);

				if (typeof (value) === 'string') {
					if (wildcard.test(value) || at.test(value) || regexpHost.test(asciiStr))
						resultValidate = true;
					else
						resultValidate = this.regEx('domain_notld', null, null, null, null, value);
				}
				break;
			case 'host_ptr':
				resultValidate = false;
				if (value.length <= 127) { // 총길이 127을 넘어서는 안된다.
if (RegExp('^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$').test(value) || RegExp('^[0-9a-f]{1}(.[0-9a-f]){31}$', 'i').test(value)) {
						resultValidate = true;
					}
				}
				break;
			case 'ipv4':
			case 'record_a':
				resultValidate = RegExp('^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$').test(value);
				break;
			case 'ipv4_bandwidth':
				resultValidate = RegExp('^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}\\/(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)$').test(value);
				break;
			case 'ipv6':
			case 'record_aaaa':
				resultValidate = RegExp('^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$', 'i').test(value);
				break;
			case 'ipv4_ipv6':
				resultValidate = RegExp('^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$').test(value);

				if (!resultValidate)
					resultValidate = RegExp('^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$', 'i').test(value);
				break;
            case 'uuid':
            resultValidate = RegExp('^[0-9A-Za-z]{8}\-[0-9A-Za-z]{8}\-[0-9A-Za-z]{5}\-[0-9A-Za-z]{5}\-[0-9A-Za-z]{12}$').test(value);
                break;
			case 'record_ptr':
				resultValidate = RegExp('^(?:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}|' +
					'((?=.*::)(?!.*::.+::)(::)?([\\dA-F]{1,4}:(:|\\b)|){5}|([\\dA-F]{1,4}:){6})((([\\dA-F]{1,4}((?!\\3)::|:\\b|$))|(?!\\2\\3)){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4}))$', 'i').test(value);
				break;
			case 'record_cname':
			case 'record_mx':
			case 'record_ns':
				value = value.replace(/\\.$/, '');
				resultValidate = this.regEx('domain_notld', null, null, null, null, value);
				break;
			case 'host_wildcard':
				if (typeof (value) === 'string') {
					if (wildcard.test(value) || at.test(value))
						resultValidate = true;
					else
						resultValidate = this.regEx('domain_notld', null, null, null, null, value);
				}
				break;
			case 'password':
				var strength = '';

				if (value.length != 0) {
					if (value.match(/[0-9]/)) strength += 'A';
					if (value.match(/[a-zA-Z]/)) strength += 'B';
					if (value.match(/[\`\~\!\@\#\$\%\^\&\*\(\)\_\-\+\=\{\}\[\]\\\|\:\;\"\'\<\>\,\.\?\/]/)) strength += 'C';
					if (value.match(/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321/)) { } else strength += 'D';
					if (value.length >= 6) strength += 'E';
					if (value.match(/^(\'|\"|\#|\=|\(|\)|\+|\%|\-\-|\*\/|\\\*|\&\&|\|\||union|select|insert|from|where|update|drop|if|join|decalre|and|or|column_name|table_name|openrowset|substr|substring|xp_|sysobjects|syscolumns){1}$/)) strength += 'F';
					if (strength == 'ABCDE' || strength == 'ABCE')
						resultValidate = true;
				}
				break;
			case 'between':
				value = value.replace(/\,/gi, '');
				resultValidate = value.length > 0 && (Number(value) >= Number(minStr) && Number(value) <= Number(maxStr));
				break;
			case 'creditcard':
				resultValidate = RegExp('^(?:4[\\d]{12}(?:[\\d]{3})?|' +			// Visa
																'5[1-5][\\d]{14}|' +									// MasterCard
																'3[47][\\d]{13}|' +										// American Express
																'3(?:0[0-5]|[68][\\d])[\\d]{11}|' +		// Diners Club
																'6(?:011|5[\\d]{2})[\\d]{12}|' +			// Discover
																'(?:2131|1800|35\\d{3})\\d{11}|' +		// JCB
																'9\\d{3}\\d{12}' +										// Korean CreditCard
																')$').test(value.replace(/\-/g, ''));
				break;

		}

		return resultValidate;
	},
	// 해당 개체의 자식 요소들을 유효성 검사한다.
	children: function (e, options) {
		e.find('select,input,textarea').each(function (i, e) {
			$(e).validate(options);
		});
	},
	// 유효성 검사를 위한 요소들의 배열
	list: [],
	// 유효성 검사 개체
	tooltipObject: function (e, o) {
		var $e = $(e),
			contract = {},
			tagname = $e.prop('tagName').toLowerCase(),
			typename = $e.prop('type').toLowerCase();

		// 개체의 계약값에 넣어준다.
		e._contract = contract;

		// 기본 옵션 및 사용자 정의 옵션 설정
		contract.options = {
			'regex': null,
			'reserve': null,
			'modifiers': '',
			'msg': null,
			'min': null,
			'max': null,
			'speed': 200,
			'group': '',
			'special': 'None',
			'separator': null
		};

		$.validator.setOption(e, o);

		// select 요소 이거나 메세지를 포함한 예약어 및 정규식일 경우에만 유효성 플러그인을 적용한다.
		if ((tagname == 'select' && contract.options.msg) || (tagname == 'textarea' || ((tagname == 'input') && (typename == 'text' || typename == 'email' || typename == 'password')) && (contract.options.regex || contract.options.reserve) && contract.options.msg)) {

			$e.prop('validate', true);

			// 유효성을 체크할 개체를 list에 추가한다.
			$.validator.list.push(e);

			// 해당 개체를 wrap div에 개체 사이즈 및 위치에 영향을 주는 스타일을 값을 복사한다.
			var tempWidth = $e.outerWidth();
			contract.wrap = $('<div/>').css({
				'display': $e.css('display'),
				'position': $e.css('position'),
				'verticalAlign': $e.css('verticalAlign'),
				'width': $e.outerWidth() + 'px',
				'top': $e.css('top'),
				'left': $e.css('left'),
				'right': $e.css('right'),
				'bottom': $e.css('bottom'),
				'float': $e.css('float'),
				'clear': $e.css('clear'),
				'marginTop': $e.css('marginTop'),
				'marginLeft': $e.css('marginLeft'),
				'marginRight': $e.css('marginRight'),
				'marginBottom': $e.css('marginBottom')
			});

			// 해당 개체의 위치 스타일을 제거하고 wrap div 와 replace 한다.
			$e.addClass('valdate_alignment').css({
				'display': 'inline',
				'verticalAlign': 'baseline',
				'top': 0,
				'left': 0,
				'right': 0,
				'bottom': 0,
				'float': 'left',
				'clear': 'both',
				'margin': 0
			}).width('100%').attr({
				'tabIndex': $.validator.list.length,
				'autocomplete': 'off'
			}).before(contract.wrap).appendTo(contract.wrap);

			// 엘리먼트 가로 세로 크기를 재계산 해준다.(padding 과 border-width 값을 빼준다)
			var spanBorderWidth = (parseInt($e.css('borderLeftWidth'), 10) | 0) + (parseInt($e.css('borderRightWidth'), 10) | 0),
				spanPaddingWidth = (parseInt($e.css('paddingLeft'), 10) | 0) + (parseInt($e.css('paddingRight'), 10) | 0),
				newWidth = tagname == 'select' ? tempWidth : tempWidth - spanBorderWidth - spanPaddingWidth;

			$e.css({
				'width': newWidth + 'px'
			});

			// 유효성 메세지 개체를 만들고 검사개체 다음에 삽입한다.
			contract.box = $('<div/>')
				.addClass('validate_tooltip valdate_alignment')
				.width($e.innerWidth())
				.append(
					$('<div/>').addClass('validate_message'),
					$('<input type=\"button\"/>').val('▲').addClass('validate_close').on('click', function () {
						contract.box.slideUp(contract.options.speed, function () {
							$(this).prop('validate_view', false);
						});
					})
				);

			// 메세지 엘리먼트의 top위치를 계산해준다.
			var borderBottomSize = parseInt($e.css('borderBottomLeftRadius'), 10) || 0;
			borderBottomSize = borderBottomSize == 0 ? parseInt($e.css('borderBottomWidth'), 10) || 0 : borderBottomSize;

			$e.after(contract.box
				.hide()
				.css({
					'top': -borderBottomSize + 'px',
					'borderStyle': $e.css('borderLeftStyle'),
					'borderWidth': $e.css('borderLeftWidth'),
					'borderColor': $e.css('borderLeftColor'),
					'borderTop': 'none'
				})
			);

			// tagname 에 따라 다른 이벤트를 바인딩 한다.
			if (tagname == 'input' || tagname == 'textarea') {
				$e
					.on('alert', function (event, msg) { $.validator.alert.call(e, msg); })
					.on('keyup', function (event) { $.validator.checkText.call(e); })
					.on('paste', function (event) { setTimeout(function () { $.validator.checkText.call(e); }, 0); })
					.on('check', function (event) { $.validator.checkText.call(e); });
			}
			else if (tagname == 'select') {
				$e
					.on('alert', function (event, msg) { $.validator.alert.call(e, msg); })
					.on('change', function (event) { $.validator.checkSelect.call(e); })
					.on('check', function (event) { $.validator.checkSelect.call(e); });
			}
		}
		else if (tagname == 'input' && typename == 'checkbox') {
			$e.prop('validate', true);

			// 유효성을 체크할 개체를 list에 추가한다.
			$.validator.list.push(e);

			contract.box = $('<div/>').addClass('validate_checkbox')
				.on('click', function () {
					$e.trigger('click');
					$.validator.checkCheckBox.call(e);
				})
				.on('change', function () {
					$e.trigger('change');
					$.validator.checkCheckBox.call(e);
				})
				.on('check', function () {
					$.validator.checkCheckBox.call(e);
				});

			$e
				.on('change', function () {
					$.validator.checkCheckBox.call(e);
				})
				.before(contract.box).oHide();

			if ($e.prop('checked')) {
				contract.box.addClass('validated validate_checked').removeClass('invalidate_checked');
				$e.prop('result', true);
			}
		}
	},
	// 사용 자 정의 옵션을 세팅한다.
	setOption: function (e, o) {
		var $e = $(e),
			options = e._contract.options;
		$.each(options, function (name, value) {
			if ($e.attr(name)) {
				options[name] = $e.attr(name);
				$e.removeAttr(name);
			}
		});
		options = $.extend(options, o);

		// 예약어가 있을경우 정규식을 생성한다. 
		if (options.reserve) {
			options.regex = $.validator.genRegex(options);
		}
	},
	// 강제로 경고 메세지를 띄운다.
	alert: function (alertMsg) {
		var $e = $(this),
			options = this._contract.options,
			box = this._contract.box,
			msg = box.find('.validate_message')

		if (!box.prop('validate_view')) {
			msg.html(alertMsg);
			box.css('z-index', 1).slideDown(Number(options.speed), function () {
				$(this).prop('validate_view', true);
			});
		} else {
			box.css('z-index', 1).slideDown(Number(options.speed), function () {
				$(this).prop('validate_view', true);
				msg.html(alertMsg);
			});
		}

		$e.addClass('invalidate').removeClass('validated').prop('result', false);
	},
	// checkbox 요소의 체크 여부를 검사한다.
	checkCheckBox: function () {
		var $e = $(this);
		if ($e.prop('validate')) {
			var checkStat = $e.prop('checked'),
				box = this._contract.box;
			if (checkStat) {
				box.addClass('validated validate_checked').removeClass('invalidate_checked');
				$e.prop('result', true);
			}
			else {
				box.addClass('invalidate_checked').removeClass('validated validate_checked');
				$e.prop('result', false);
			}
		}
	},
	// input,textarea 요소의 유효성 검사 이벤트
	checkText: function () {
		var $e = $(this);
		if ($e.prop('validate')) {
			var options = this._contract.options,
				box = this._contract.box,
				msg = box.find('.validate_message'),
				texts = options.separator ? $e.val().split(new RegExp(options.separator, 'g')) : [$e.val()],
				resultValidate = false;

			if ($.trim($e.val()) == '' && RegExp('(?:n\/a|blank)', 'gi').test(options.reserve)) {
				resultValidate = true;
				texts = [];
			}

			for (var i = 0; i < texts.length; texts[i] = $.trim(texts[i]), i++) {
				resultValidate = $.validator.regEx(options.special, options.regex, options.min, options.max, options.modifiers, $.trim(texts[i]));
				if (!resultValidate) {
					break;
				}
			}

			if (!resultValidate) {
				if (!box.prop('validate_view')) {
					msg.html(options.msg);
					box.css('z-index', 1).slideDown(Number(options.speed), function () {
						$(this).prop('validate_view', true);
					});
				} else {
					msg.html(options.msg);
				}
				$e.addClass('invalidate').removeClass('validated').prop('result', false);
			} else {
				box.slideUp(Number(options.speed), function () {
					msg.html('');
					$(this).prop('validate_view', false);
				});

				if ($.trim($e.val()) == '') {
					$e.removeClass('validated invalidate');
				}
				else {
					$e.removeClass('invalidate').addClass('validated');
				}
			}
		}
	},
	// select 요소의 유효성 검사 이벤트
	// 0번째 option 외의 option 을 선택해야 유효성검사가 통과한다.
	checkSelect: function () {
		var $e = $(this);
		if ($e.prop('validate')) {
			var options = this._contract.options,
				box = this._contract.box,
				msg = box.find('.validate_message'),
				selectedIndex = $e.find(':selected').index();
			if ($e.val() == null || $e.val() == '') {
				if (!box.prop('validate_view')) {
					msg.html(options.msg);
					box.css('z-index', 1).slideDown(Number(options.speed), function () {
						$(this).prop('validate_view', true);
					});
				} else {
					$e.prop('result', false);
					msg.html(options.msg);
				}
				$e.addClass('invalidate').removeClass('validated').prop('result', false);
			}
			else {
				$e.removeClass('invalidate').addClass('validated');
				box.slideUp(Number(options.speed), function () {
					msg.html(options.msg);
					$(this).prop('validate_view', false);
				});
			}
		}
	},
	// 유효성 체크를 한다.
	// callback이 있을경우 유효성 검사가 통과하면 callback을 실행한다.
	// 그룹명이 있을경우 해당 그룹명의 요소만 유효성 검사를 진행한다.
	check: function (callback, groupName, callbackError) {
		var i = 0,
			result = true,
			list = this.list,
			checkList = [];

		if (groupName) {
			$.each(list, function (i, e) {
				var $e = $(e),
					typename = $e.prop('type').toLowerCase(),
					options = e._contract.options,
					group = options.group,
					groupArray = group.split(/\s/g),
					$virtuale = typename == 'checkbox' ? $e.prev('div.validate_checkbox') : $e;

				for (var i = 0; i < groupArray.length; i++) {
					if ($virtuale.is(':visible') && groupArray[i] == groupName) {
						checkList.push(e);
						break;
					}
				}
			});
		}
		else
			checkList = list;

		$.each(checkList, function (i, e) {
			var $e = $(e),
				tagName = $e.prop('tagName').toLowerCase(),
				typename = $e.prop('type').toLowerCase(),
				trigerName = null;

			switch (tagName) {
				case 'input':
				case 'textarea':
					if (typename == 'checkbox') {
						trigerName = 'change';
					}
					else {
						trigerName = 'keyup';
					}
					break;
				case 'select':
					trigerName = 'check';
					break;
			}

			if (!$e.prop('result', true).trigger(trigerName).prop('result')) {
				result = false;
			}
		});

		if (result && callback)
			callback.call(this);
		else if (!result && callbackError)
			callbackError.call(this);
	}
}
})(jQuery);
