function formToJson(formId) {
	var form = document.getElementById(formId);
	var json = Array.from(new FormData(form)).map(function(e, i) {
		this[e[0]] = e[1];
		return this;
	}.bind({}))[0];
	return json;
}

function queryBinaryIndexJobProgress(taskname, holder, callback, removeOnComplete=false) {

	var statusMap = {};
	var maxStage = 0;

	function merge() {
		var array_keys = [];
		for ( var key in statusMap)
			if (statusMap[key] != -1)
				array_keys.push(parseInt(key));
		while (statusMap[maxStage] != undefined) {
			maxStage = maxStage + 1;
		}
		array_keys.push(maxStage);
		console.log(array_keys);
		return array_keys;
	}

	var timeOutQuery = null;
	subQuery(callback);
	function subQuery(callback) {
		if (timeOutQuery != null)
			clearTimeout(timeOutQuery);
		$.ajax({
			type : "GET",
			url : '/JobProgress',
			data : {
				task : taskname,
				indexes : merge().toString()
			},
			success : function(snyData) {

				if (snyData['error']) {
					alert(snyData['error']);
					return;
				}

				var progress = snyData['progress'];

				progress.stages.forEach(function(stage) {
					var progressBar = statusMap[stage.ind];
					if (undefined == progressBar)
						progressBar = createProgressBar(stage.msg, holder);
					var percent = Math.round(stage.progress * 100) + '%';
					var bar = progressBar.find('.progress-bar');
					bar.css({
						width : percent
					});
					$(progressBar.find('span')[0]).html(stage.msg);
					$(progressBar.find('span')[1]).html(percent);
					statusMap[stage.ind] = progressBar;
					if (stage.completed == true) {
						statusMap[stage.ind] = -1;
						bar.parent().removeClass('active');
						if(!progress.completed && removeOnComplete)
							bar.parent().parent().remove();
					}
					if (stage.progress >= 1) {
						bar.addClass('progress-bar-success')
					}
				});

				if (progress.completed == true) {
					callback(progress);
				} else {
					timeOutQuery = setTimeout(function() {
						subQuery(callback);
					}, 3000);
				}

			}
		});

	}

}

function createProgressBar(msg, holder) {
	var $pdiv = $("<div>", {});
	var $div = $("<div>", {});
	var $span2 = $("<span>", {
		'class' : 'progress-label'
	}).html('Status: ' + msg);
	$div.append($span2);
	var panel = $(holder);
	$pdiv.append($div);
	panel.append($pdiv);
	$div = $("<div>", {
		'class' : 'progress progress-striped active'
	});
	$pdiv.append($div);
	var $divp = $("<div>", {
		'class' : 'progress-bar'
	});
	$divp.css({
		width : "0%"
	});
	$div.append($divp);
	$div.append($("<span>", {}).html('0%'));
	return $pdiv;
}

function dmas_alert(msg){
	
	$('#alert-message').text(msg);
	$('#btnTrigger').click();
}

function drawFixedBox($box, init_func){
	var right = $box.data('right');
	var width = $box.width();
	var offset = right - width;
	var shown = false;
	var first = true;
	console.log(offset);
	$box.css('right', offset);
	$(window).click(function() {
		if(shown){
			$box.css({ 'right': '0px', 'left': '' }).animate({
                'right' : offset
            });
			shown = false;
		}
	});
	
	$box.find('span').click(function(e){
		if(!shown){
			$box.css({ 'right': offset, 'left': '' }).animate({
                'right' : '0px'
            });
			shown = true;
			if(first){
				init_func();
			}
			first = false;
			e.stopPropagation();
		}
	});
	$box.click(function(e){
		e.stopPropagation();
	})
}


var search_call_backs = []
$(function(){
	// check and create search box (for embedded browser)
	if (typeof browser_controller !== 'undefined' && browser_controller.search){
		$input = $('<input>', {'class':'form-control pull-left', 'type':'text', 'placeholder':'Press Enter to Search'})
		$btn = $('<i>', {'class':'material-icons pull-left'}).text('search');
		$box = $('<div>', {'class':'fixed-search-box'}).append($btn).append($input);
		$input.on('keyup', function (e) {
		    if (e.keyCode == 13) {
		    	 browser_controller.search($input.val());
		    	 $.each(search_call_backs, function(indx,func){func();});
		    }
		});
		$(window).on('keyup', function (e) {
		    if (e.keyCode == 13) {
		    	 browser_controller.search($input.val());
		    }
		});
		$(window).keyup(function(e){
        	if(e.keyCode == 27) {
        		browser_controller.stop_search();
        		shown = false;
				$box.css({ 'right': '0px', 'left': '' }).animate({
	                'right' : '-158px'
	            });
            }
        });
		
		$('body').append($box);
		$box.click(function(e) {
			e.stopPropagation();
	    });
		var shown = false;
		$btn.click(function(e){
			if(!shown){
				shown = true;
				$('.fixed-search-box').css({ 'right': '-158px', 'left': '' }).animate({
	                'right' : '0px'
	            });
				e.stopPropagation();
			}
		});
		$(window).on('keydown', function(e){
			if(e.ctrlKey && e.keyCode === 70 && !shown){
				shown = true;
				$input.focus()
				$('.fixed-search-box').css({ 'right': '-158px', 'left': '' }).animate({
	                'right' : '0px'
	            });
				e.stopPropagation();
			}
		});
		$input.click(function(e){
			e.stopPropagation();
		})
		$(window).click(function() {
			if(shown){
				shown = false;
				$('.fixed-search-box').css({ 'right': '0px', 'left': '' }).animate({
	                'right' : '-158px'
	            });
			}
		});
	}
});
