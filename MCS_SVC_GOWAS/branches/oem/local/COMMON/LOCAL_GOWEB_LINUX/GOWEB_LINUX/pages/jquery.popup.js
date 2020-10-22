var resizer = {
  set: function (selector) {
    this.selector = selector;
  },
  resize: function () {
    $(this.selector).popup('resize');
  }
}

; (function ($) {
  $.popup = function (p, o) {
    var settings = $.extend({
      'width': 400,
      'height': 200,
			'method': 'get',
      'title': 'Noname',
      'titleClose': 'Close',
      'closeBtn': true
    }, o);

    if (p.g)
      return false;

    var g = {
      popup: null,
      body: null,
      init: function () {
        var $this = $(p),
					$bg = $('<div></div>').addClass('bg'),
					$ifrmWrap = $('<div></div>').attr('id', 'ifrmWrap'); //.addClass('pop_w');

        if (!g.popup) {
          g.popup = $('<div></div>').addClass('popWrapper').hide();
        }

        g.popup.css('overflow-y', 'auto').append($bg);
				g.popup.append($ifrmWrap);
        g.popup.insertBefore($this.find(':first'));
      },
      open: function (o) {
        var $bg = g.popup.find('.bg'),
					$ifrmWrap = g.popup.find('#ifrmWrap'),
					$close = $('<a />').addClass('close').attr({
					  'href': '#',
					  'title': settings.titleClose
					}).text('X'),
					screenWidth = $(window).width(), 
					screenHeight = $(window).height(),
					left = 0,
					width = 0;
				
        if (o.width)
          width = o.width;
        else
          width = settings.width;

        if (o.close)
          settings.close = o.close;
        else
          settings.close = null;

        $close.on('click', function (e) {
          e.preventDefault();
          g.close();
        });

				var screenWidth = $(window).width(), 
					left = Number(screenWidth / 2);

				if (width)
					left = Number((screenWidth - width) / 2);

					$ifrmWrap.css({'left': left, 'height': '100%'});
				//$ifrmWrap.css({'width': width, 'left': left, 'height': 0});

        if (g.popup)
          g.popup.css('visibility', 'visible');

        if (o.url) {
					var url = o.url;
					var splitter = '?';

					if (url && url.indexOf('?') > -1)
						splitter = '&';

					if(o.width) {
							url += splitter + 'w=' + o.width;
					};

					var $iframe = $('<iframe />');
					$iframe.css({
						'width': '100%',
						'height': '100%'
					}).attr({
						'id': 'ifrmPopup',
						'name': 'ifrmPopup',
						'frameborder': 0,
						'scrolling': 'no'
					});

					$ifrmWrap.empty().append($iframe);

					url += '&_=' + (new Date()).getTime();
					url += "&popup=1";

					if(o.method == 'post') {
						$iframe.attr('src', '');
						var $form = $('<form />').css({'width': '0px', 'height': '0px'}).attr('action',url).attr('method', 'post').attr('target', 'ifrmPopup');
						if(o.data) {
							$.each((typeof(o.data) == 'object' ? o.data : JSON.parse(o.data)), function(k, v) {
								var $input = $('<input />').attr('type', 'hidden').attr('name', k).attr('value', (typeof(v) == 'object' ? JSON.stringify(v) : v));
								$form.append($input);
							});
						};
						g.popup.append($form);
						$form.submit();
					}
					else {
						$iframe.attr('src', url);
					};

					g.popup.show();
        };

        $('body').css('overflow-y', 'hidden');
      },
      resize: function (currentHeight) {
        var $ifrmWrap = g.popup.find('#ifrmWrap'), 
          $bg = g.popup.find('.bg'),
					screenHeight = $(window).height();

				if(typeof(currentHeight) != 'number') {
					currentHeight = '100%';
					//var $iframe = g.popup.find('#ifrmPopup');
					//currentHeight = $iframe.contents().height();
				}
        
				var popHeight = currentHeight + 58,
					top = 0,
					padding = 20;

        top = parseInt((screenHeight - popHeight) / 2);
        if (top < 0)
          top = 0;

        if (screenHeight < popHeight)
          $bg.css('height', currentHeight + 60);
				/*
        $ifrmWrap.css({
          'visibility': 'visible'
        }).animate({
          'height': currentHeight,
          'top': top + padding
        }, 100, function () {
          if (g.popup)
            $bg.height(g.popup.get(0).scrollHeight);
        });
				*/
      },
      close: function (callback) {
        
        $('body').css('overflow-y', 'auto');

        if (!callback || typeof callback != 'function')
          callback = settings.close;

        if (g.popup) {
					var $ifrmWrap = g.popup.find('#ifrmWrap');
					$ifrmWrap.empty().css('height', '0px');
					g.popup.hide();
          if (callback)
            callback.call(this);
        };
      }
    };

    g.init();

    p.g = g;
  };

  $.fn.popup = function (p) {
    var args = arguments;

    if (args.length > 1)
      args = args[1];
    else
      args = [];
    resizer.set(this);

    return this.each(function () {
      if (!this.g && typeof p === 'object') {
        $.popup(this, p);
      }
      else if (this.g && typeof p === 'string') {
        if (this.g[p.toLowerCase()])
          this.g[p.toLowerCase()].call(this, args);
      }
    });
  };
})(jQuery);

function resizePopHeight() {
  setTimeout(function () { resizer.resize(); }, 0);
}