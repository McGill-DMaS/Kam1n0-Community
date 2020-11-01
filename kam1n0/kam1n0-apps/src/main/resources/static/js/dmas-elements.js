/**
 * Merge the multiple clone search unit.
 * 
 * @param dps
 * @returns
 */
function mergeCloneResult(dps){
    var dp = {};
    var results = [];
    for(var odp of dps)
    	results = results.concat(odp['results']);
    dp['results'] = results;
    dp['cloneGraph'] = {};
    var links = [];
    var nodes = [];
    dp['cloneGraph']['links'] = links;
    dp['cloneGraph']['nodes'] = nodes;


    // translate binary id
    var bidMap = {};
    for(var res of dp['results']){
        bidMap[res['function']['binaryId']] = -1;
        for(var clone of res['clones']){
            bidMap[clone['binaryId']] = -1;
        }
    }

    var bid = 0;
    for(var id in bidMap){
        bidMap[id] = bid;
        bid += 1;
    }


    // translate function id
    var fidMap = {}
    var fid = 0
    for(var res of dp['results']){
        var func = res['function'];
        if (!fidMap[func['functionId']]){
            fidMap[func['functionId']] = fid;
            fid += 1;
            var node = {};
            node['binaryGroupID'] = bidMap[func['binaryId']];
            node['binaryGroupName'] = func['binaryName'];
            node['clones'] = [];
            node['name'] = func['functionName'];
            nodes.push(node);
        }
    }

    for(var res of dp['results']){
        for(var clone of res['clones']){
            if (clone['functionId'] in fidMap)
            		continue;
                fidMap[clone['functionId']] = fid;
                fid += 1;
                snode = {};
                snode['binaryGroupID'] = bidMap[clone['binaryId']];
                snode['binaryGroupName'] = clone['binaryName'];
                snode['clones'] = [];
                snode['name'] = clone['functionName'];
                nodes.push(snode);
            
        }
    }

    // generate link
    for (var res of dp['results']){
        var func = res['function'];
        for (var clone of res['clones']){
            var link = {};
            link['source'] = fidMap[func['functionId']];
            link['target'] = fidMap[clone['functionId']];
            link['value'] = clone['similarity'];

            var node = nodes[link['source']];
            if(typeof node == 'undefined')
            	continue;
            node['clones'].push([link['target'], link['value']]);

            node = nodes[link['target']];
            if(typeof node == 'undefined')
            	continue;
            node['clones'].push([link['source'], link['value']]);

            links.push(link);
        }
    }

    return dp
	
}

/*******************************************************************************
 * 
 * @param $container
 * @param dataParsed
 * @param callback
 * @param iconsAndLinks
 *            what icon and link should be added as prefix.
 * @returns
 */
function CreateClusterCloneList($container, dataParsed, callback, icons, views, viewnames, isPercent=true, open_all=false, margin_top=-30){
	
		var interaction = false;
		if(typeof send_msg != 'undefined')
			interaction = true;
	
		$header = $("<div>", {'class': 'row', 'style': 'margin-left: 0; margin-right: 0; margin-top:' + margin_top + 'px;'})
		$list = $("<div>", {'class': 'row', 'style': 'margin-left: 0; margin-right: 0;'})
		$container.append($header)
		$container.append($list)
		
		$select = $('<select>', {'class': 'form-control', 'placeholder':'sort'})
		$search = $('<input>', {'class': 'form-control', 'type': 'text', 'placeholder': "Search (1s delay on keydown)"})
		$download = $('<button>', {'class': 'btn btn-primary btn-simple btn-sm', 'style': 'font-size:10pt; top:-5px', 'title':'Download'}).append(
				$('<i>', {'class': 'material-icons'}).text('file_download')
		).append($('<span>').text(''))
		$expandall = $('<button>', {'class': 'btn btn-primary btn-simple btn-sm', 'style': 'font-size:10pt; top:-5px', 'title':'Open All'}).append(
				$('<i>', {'class': 'material-icons'}).text('add')
		).append($('<span>').text(''))
		$closeall = $('<button>', {'class': 'btn btn-primary btn-simple btn-sm', 'style': 'font-size:10pt; top:-5px', 'title':'Collapse All'}).append(
				$('<i>', {'class': 'material-icons'}).text('remove')
		).append($('<span>').text(''))
		$header.append(
				$("<div>", {'style': 'width: 200px', 'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<span>", {'class': 'input-group-addon'}).append(
										$("<i>", {'class': 'material-icons'}).text('keyboard_arrow_right')
								)
						).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$select
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 250px', 'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<span>", {'class': 'input-group-addon'}).append(
										$("<i>", {'class': 'material-icons'}).text('keyboard_arrow_right')
								)
						).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$search
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 30px',  'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$download
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 30px',  'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$expandall
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 30px',  'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$closeall
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		
		$menu = createDropDownMenu($header);
		$menu.css('margin-top','35px')
		$menu.removeClass('pull-right')
		$menu.addClass('pull-left')
		
		function sort_by_name(a, b){
			var a1 = this.get_node(a);
            var b1 = this.get_node(b);
            var alv = a1.a_attr['lvl'];
            var blv = b1.a_attr['lvl'];
            if (alv == blv && alv == 2){
                return (a1.a_attr.per < b1.a_attr.per) ? 1 : -1;
            } else if (alv == blv && alv == 1){
            	var selvar = $select.val()
            	if (selvar == 0)
            		return (a1.a_attr.func.functionName > b1.a_attr.func.functionName) ? 1 : -1;
            	if (selvar == 1)
            		return (a1.a_attr.func.startAddress > b1.a_attr.func.startAddress) ? 1 : -1;
            	if (selvar == 2)
            		return (a1.a_attr.func.blockSize < b1.a_attr.func.blockSize) ? 1 : -1;
            	if (selvar == 3)
            		return (a1.a_attr.per < b1.a_attr.per) ? 1 : -1;
            } else {
            	return (alv < blv) ? 1 : -1;
            }
		}

		
		var bins = {};
		
		var treeData = [];
        var root = {};
        root.icon = false;
        root.text = "<i class='fa fa-fw  fa-briefcase'></i>&nbsp;" + dataParsed.results[0].function.binaryName + "&nbsp;[" + dataParsed.results.length + " functions]";
        root.children = [];
        root.a_attr = {'lvl': 0};
        treeData.push(root);
        $.each(dataParsed.results, function( ind, val ) {
            var node = {};
            var percentage = 0;
            node.children = [];
            node.icon = false;
            node.id = ind.toString();
            $.each(val.clones, function(cind, clone){
            	bins[clone.binaryId] = clone.binaryName;
                var child = {};
                var percentage = 0
                percentage = isPercent?(clone.similarity * 100):clone.similarity;
                percentage = Math.round(percentage * 100) / 100;
                child.percentage = percentage;
                var links = "";
                for(var i = 0; i < icons.length; ++i)
                	links += '<span title=\"'+ viewnames[i] +'\" onClick=\"javascript:window.open(\'' + views[i] + 
                	'?id1='+ dataParsed.results[0].function.functionId + 
                	"&id2=" + clone.functionId + 
                	"&in1=" + ind + 
                	"&in2=" + cind + 
                	'\')\">' + icons[i] + '</span> ';
                var prefix;
                if(isPercent)
                    prefix = "<div style='display:inline-block' class=\"sparkpie\" data-percent=\"" + percentage + "\"></div>&nbsp;" + links;
                else
                	prefix = "<span class=\"sparkpie\">" + percentage +"</span>&nbsp;" + links;
                child.text = prefix + clone.functionName;
                child.children = [];
                child.icon = false;
                node.children.push(child);
                child.a_attr = {'data-pair':[ind, cind], 'per': percentage, 'lvl': 2, 'bid':clone.binaryId};
                child.id = [ind, cind].toString();
                child.lvl = 2
            });
            node.children.sort(function(a, b){return b.percentage - a.percentage;});
            if(node.children[0] != null)
                percentage = node.children[0].percentage;
            var icon
            if(isPercent)
                icon = "<i class='fa fa-fw fa-sitemap'></i><div style='display:inline-block' class=\"sparkpie\" data-percent=\"" + percentage + "\"></div>&nbsp;";
            else
            	icon = "<i class='fa fa-fw fa-sitemap'></i><span class=\"sparkpie\">" + percentage +"</span>&nbsp;";
            node.percentage = percentage;
            node.text = icon + val.function.functionName + " [" + val.function.blockSize + " blks] start effective address: " + val.function.startAddress;
            node.lvl = 1;
            node.a_attr = {'per': percentage, 'func':  val.function, 'lvl': 1};
            root.children.push(node);
        });

        // root.children.sort(function(a, b){return b.percentage -
		// a.percentage;});
        
        var tree_settings = {
                'core' : {
                    "themes" : { },
                    "check_callback" : true,
                    'data' : treeData
                },
                "plugins" : [ "search", "sort" ],
                "sort" : sort_by_name,
                "search":{
                	"show_only_matches": true,
                }
        };
        if(interaction){
        	tree_settings["plugins"].push("contextmenu");
        	tree_settings["contextmenu"] = {
        			"items": function(node){
        				var addr = parseInt(node.a_attr.func.startAddress);
        				var addr = "0x" + addr.toString(16);
        				var items = {
        				        "jumpto": { 
        				            label: "Jump to " + addr + " in IDA",
        				            icon: "fa fa-fw fa-mail-reply",
        				            action: function () {
        				            	send_msg("jumpto("+addr +")");
        				            }
        				        }
        				    };
        				if(node.a_attr.lvl == 1)
        					return items;
        				return {};
        			}
        	}
        }
        

        $list.
        on('open_node.jstree', function (e, data) {
        	if(isPercent){
	            // if($('#'+data.node.id).find('.sparkpie canvas').length != 0)
	            // $('#'+data.node.id).find('ul').find('.sparkpie').sparkline('html',
	            // {type: 'pie', height: '1.2em', sliceColors:
				// ['#dddddd','#dc3912'], tooltipFormatFieldlist: ['percent'],
				// });
	            // else
	            // $('#'+data.node.id).find('.sparkpie').sparkline('html',
	            // {type: 'pie', height: '1.2em', sliceColors:
				// ['#dddddd','#dc3912'], tooltipFormatFieldlist: ['percent'],
				// });
        		 $('#'+data.node.id).find('ul').find('.sparkpie').each(function(index,item){
        			if($(item).children().length<1)
        		 	new d3pie(item, {
							"size": {
								"canvasWidth": 20,
								"canvasHeight": 20,
								"pieOuterRadius": "100%"
							},
							"labels" : {
								"inner" :{
									"format": "none"
								},
								"outer" :{
									"format":"none"
								}
							},
							"misc": {
								"canvasPadding": {
									"top": 0,
									"right": 0,
									"bottom": 0,
									"left": 0
								},
								"colors": {
                                  				"segmentStroke": "#000000"
								}
							},
							"tooltips": {
								"enabled": true,
								"type": "placeholder",
								"string": "{label}"
							},
							"data": {
								"content": [
									{ "label": "Similarity " +  $(item).data('percent') + "%", "value": 100-$(item).data('percent'), "color": "#ffffff" },
									{ "label": "Similarity " +  $(item).data('percent') + "%", "value": $(item).data('percent'), "color": "#218812" },
								]
							}
						});
        		 });
        	}
        }).
        on('changed.jstree', function (e, data) {
            if(data.node.children.length == 0 && data.node.a_attr['data-pair'] != null){
            	callback(data.node.a_attr['data-pair']);
            }
        }).
        jstree(tree_settings
        ).on('loaded.jstree', function() {
        	if(open_all)
        		$list.jstree('open_all');
        });
        
        var to = false;
        $search.keyup(function () {
          if(to) { clearTimeout(to); }
          to = setTimeout(function () {
            var v = $search.val();
            $list.jstree(true).search(v);
          }, 1000);
        });
        $search.keyup(function(e){
        	if(e.keyCode == 27) {
        		 $(this).val('');
            }
        });
        
        $select.append(
        	$('<option>', {'text':'Sort by Name', 'selected': 'true', 'value': 0})
        ).append(
        	$('<option>', {'text':'Sort by Start Effective Address', 'value': 1})
        ).append(
        	$('<option>', {'text':'Sort by Number of Blocks', 'value': 2})
        ).append(
            	$('<option>', {'text':'Sort by Similarity', 'value': 3})
        ).on('change', function() {
        	  $list.jstree(true).sort($list.jstree(true).get_node('#'), 1);
        	  $list.jstree('close_all');
        	  if(open_all)
        		  $list.jstree('open_all');
        });
        $closeall.click(function(){ $list.jstree('close_all')});
        $expandall.click(function(){ $list.jstree('open_all')});
        
        $download.click(function(){
        	var wrapper = {'data':dataParsed, 'view': window.location.href }
        	$("<a />", {
        	    "download": "results.json",
        	    "href" : "data:application/json," + encodeURIComponent(JSON.stringify(wrapper, null, 2))
        	  }).appendTo("body")
        	  .click(function() {
        	     $(this).remove()
        	  })[0].click()
        });
        
        $box = createBinarySelectionMenu(bins);
        console.log($box)
        $menu.add_menu_item('Filter by Source Binaries', [$box])
        $box.onselection = function(inverse_selected){
        	if(inverse_selected.length == 0){
        		 $list.jstree(true).show_all();
        	}else{
        		$($list.jstree().get_json($list, {
        	          flat: true
        	        })).each(function(index, value) {
        	          if(value.a_attr.lvl==2 && inverse_selected.has(value.a_attr.bid)){
        	        	  $list.jstree(true).hide_node(value);
        	          }else{
        	        	  $list.jstree(true).show_node(value);
        	          }
        	    });
        		root = $list.jstree(true).get_node('#').children[0];
        		$list.jstree(true).close_node(root);
        		$list.jstree(true).open_node(root);
        	}
        }
        $box.init()

    }

/*******************************************************************************
 * 
 * @param $container
 * @param dataParsed
 * @param callback
 * @param iconsAndLinks
 *            what icon and link should be added as prefix.
 * @returns
 */
function CreateCloneList($container, dataParsed, callback, icons, views, viewnames, isPercent=true, open_all=false, margin_top=-30){
	
		var interaction = false;
		if(typeof send_msg != 'undefined')
			interaction = true;
	
		$header = $("<div>", {'class': 'row', 'style': 'margin-left: 0; margin-right: 0; margin-top:' + margin_top + 'px;'})
		$list = $("<div>", {'class': 'row', 'style': 'margin-left: 0; margin-right: 0;'})
		$container.append($header)
		$container.append($list)
		
		$select = $('<select>', {'class': 'form-control', 'placeholder':'sort'})
		$search = $('<input>', {'class': 'form-control', 'type': 'text', 'placeholder': "Search (1s delay on keydown)"})
		$download = $('<button>', {'class': 'btn btn-primary btn-simple btn-sm', 'style': 'font-size:10pt; top:-5px', 'title':'Download'}).append(
				$('<i>', {'class': 'material-icons'}).text('file_download')
		).append($('<span>').text(''))
		$expandall = $('<button>', {'class': 'btn btn-primary btn-simple btn-sm', 'style': 'font-size:10pt; top:-5px', 'title':'Open All'}).append(
				$('<i>', {'class': 'material-icons'}).text('add')
		).append($('<span>').text(''))
		$closeall = $('<button>', {'class': 'btn btn-primary btn-simple btn-sm', 'style': 'font-size:10pt; top:-5px', 'title':'Collapse All'}).append(
				$('<i>', {'class': 'material-icons'}).text('remove')
		).append($('<span>').text(''))
		$header.append(
				$("<div>", {'style': 'width: 200px', 'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<span>", {'class': 'input-group-addon'}).append(
										$("<i>", {'class': 'material-icons'}).text('keyboard_arrow_right')
								)
						).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$select
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 250px', 'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<span>", {'class': 'input-group-addon'}).append(
										$("<i>", {'class': 'material-icons'}).text('keyboard_arrow_right')
								)
						).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$search
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 30px',  'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$download
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 30px',  'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$expandall
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		$header.append(
				$("<div>", {'style': 'width: 30px',  'class': 'pull-left'}).append(
						$("<div>", {'class': 'input-group'}).append(
								$("<div>", {'class': 'form-group label-floating'}).append(
										$closeall
								).append(
										$('<span>', {'class': 'material-input'})
								)
						)
				)
		);
		
		$menu = createDropDownMenu($header);
		$menu.css('margin-top','35px')
		$menu.removeClass('pull-right')
		$menu.addClass('pull-left')
		
		function sort_by_name(a, b){
			var a1 = this.get_node(a);
            var b1 = this.get_node(b);
            var alv = a1.a_attr['lvl'];
            var blv = b1.a_attr['lvl'];
            if (alv == blv && alv == 2){
                return (a1.a_attr.per < b1.a_attr.per) ? 1 : -1;
            } else if (alv == blv && alv == 1){
            	var selvar = $select.val()
            	if (selvar == 0)
            		return (a1.a_attr.func.functionName > b1.a_attr.func.functionName) ? 1 : -1;
            	if (selvar == 1)
            		return (a1.a_attr.func.startAddress > b1.a_attr.func.startAddress) ? 1 : -1;
            	if (selvar == 2)
            		return (a1.a_attr.func.blockSize < b1.a_attr.func.blockSize) ? 1 : -1;
            	if (selvar == 3)
            		return (a1.a_attr.per < b1.a_attr.per) ? 1 : -1;
            } else {
            	return (alv < blv) ? 1 : -1;
            }
		}

		
		var bins = {};
		
		var treeData = [];
        var root = {};
        root.icon = false;
        root.text = "<i class='fa fa-fw  fa-briefcase'></i>&nbsp;" + dataParsed.results[0].function.binaryName + "&nbsp;[" + dataParsed.results.length + " functions]";
        root.children = [];
        root.a_attr = {'lvl': 0};
        treeData.push(root);
        $.each(dataParsed.results, function( ind, val ) {
            var node = {};
            var percentage = 0;
            node.children = [];
            node.icon = false;
            node.id = ind.toString();
            $.each(val.clones, function(cind, clone){
            	bins[clone.binaryId] = clone.binaryName;
                var child = {};
                var percentage = 0
                percentage = isPercent?(clone.similarity * 100):clone.similarity;
                percentage = Math.round(percentage * 100) / 100;
                child.percentage = percentage;
                var links = "";
                for(var i = 0; i < icons.length; ++i)
                	links += '<span title=\"'+ viewnames[i] +'\" onClick=\"javascript:window.open(\'' + views[i] + 
                	'?id1='+ dataParsed.results[0].function.functionId + 
                	"&id2=" + clone.functionId + 
                	"&in1=" + ind + 
                	"&in2=" + cind + 
                	'\')\">' + icons[i] + '</span> ';
                var prefix;
                if(isPercent)
                    prefix = "<div style='display:inline-block' class=\"sparkpie\" data-percent=\"" + percentage + "\"></div>&nbsp;" + links;
                else
                	prefix = "<span class=\"sparkpie\">" + percentage +"</span>&nbsp;" + links;
                child.text = prefix + clone.functionName + " @ " + clone.binaryName;
                child.children = [];
                child.icon = false;
                node.children.push(child);
                child.a_attr = {'data-pair':[ind, cind], 'per': percentage, 'lvl': 2, 'bid':clone.binaryId};
                child.id = [ind, cind].toString();
                child.lvl = 2
            });
            node.children.sort(function(a, b){return b.percentage - a.percentage;});
            if(node.children[0] != null)
                percentage = node.children[0].percentage;
            var icon
            if(isPercent)
                icon = "<i class='fa fa-fw fa-sitemap'></i><div style='display:inline-block' class=\"sparkpie\" data-percent=\"" + percentage + "\"></div>&nbsp;";
            else
            	icon = "<i class='fa fa-fw fa-sitemap'></i><span class=\"sparkpie\">" + percentage +"</span>&nbsp;";
            node.percentage = percentage;
            node.text = icon + val.function.functionName + " [" + val.function.blockSize + " blks] start effective address: " + val.function.startAddress;
            node.lvl = 1;
            node.a_attr = {'per': percentage, 'func':  val.function, 'lvl': 1};
            root.children.push(node);
        });

        // root.children.sort(function(a, b){return b.percentage -
		// a.percentage;});
        
        var tree_settings = {
                'core' : {
                    "themes" : { },
                    "check_callback" : true,
                    'data' : treeData
                },
                "plugins" : [ "search", "sort" ],
                "sort" : sort_by_name,
                "search":{
                	"show_only_matches": true,
                }
        };
        if(interaction){
        	tree_settings["plugins"].push("contextmenu");
        	tree_settings["contextmenu"] = {
        			"items": function(node){
        				var addr = parseInt(node.a_attr.func.startAddress);
        				var addr = "0x" + addr.toString(16);
        				var items = {
        				        "jumpto": { 
        				            label: "Jump to " + addr + " in IDA",
        				            icon: "fa fa-fw fa-mail-reply",
        				            action: function () {
        				            	send_msg("jumpto("+addr +")");
        				            }
        				        }
        				    };
        				if(node.a_attr.lvl == 1)
        					return items;
        				return {};
        			}
        	}
        }
        

        $list.
        on('open_node.jstree', function (e, data) {
        	if(isPercent){
	            // if($('#'+data.node.id).find('.sparkpie canvas').length != 0)
	            // $('#'+data.node.id).find('ul').find('.sparkpie').sparkline('html',
	            // {type: 'pie', height: '1.2em', sliceColors:
				// ['#dddddd','#dc3912'], tooltipFormatFieldlist: ['percent'],
				// });
	            // else
	            // $('#'+data.node.id).find('.sparkpie').sparkline('html',
	            // {type: 'pie', height: '1.2em', sliceColors:
				// ['#dddddd','#dc3912'], tooltipFormatFieldlist: ['percent'],
				// });
        		 $('#'+data.node.id).find('ul').find('.sparkpie').each(function(index,item){
        			if($(item).children().length<1)
        		 	new d3pie(item, {
							"size": {
								"canvasWidth": 20,
								"canvasHeight": 20,
								"pieOuterRadius": "100%"
							},
							"labels" : {
								"inner" :{
									"format": "none"
								},
								"outer" :{
									"format":"none"
								}
							},
							"misc": {
								"canvasPadding": {
									"top": 0,
									"right": 0,
									"bottom": 0,
									"left": 0
								},
								"colors": {
                                  				"segmentStroke": "#000000"
								}
							},
							"tooltips": {
								"enabled": true,
								"type": "placeholder",
								"string": "{label}"
							},
							"data": {
								"content": [
									{ "label": "similarity " +  $(item).data('percent') + "%", "value": 100-$(item).data('percent'), "color": "#ffffff" },
									{ "label": "similarity " +  $(item).data('percent') + "%", "value": $(item).data('percent'), "color": "#218812" },
								]
							}
						});
        		 });
        	}
        }).
        on('changed.jstree', function (e, data) {
            if(data.node.children.length == 0 && data.node.a_attr['data-pair'] != null){
            	callback(data.node.a_attr['data-pair']);
            }
        }).
        jstree(tree_settings
        ).on('loaded.jstree', function() {
        	if(open_all)
        		$list.jstree('open_all');
        });
        
        var to = false;
        $search.keyup(function () {
          if(to) { clearTimeout(to); }
          to = setTimeout(function () {
            var v = $search.val();
            $list.jstree(true).search(v);
          }, 1000);
        });
        $search.keyup(function(e){
        	if(e.keyCode == 27) {
        		 $(this).val('');
            }
        });
        
        $select.append(
        	$('<option>', {'text':'Sort by Name', 'selected': 'true', 'value': 0})
        ).append(
        	$('<option>', {'text':'Sort by Start Effective Address', 'value': 1})
        ).append(
        	$('<option>', {'text':'Sort by Number of Blocks', 'value': 2})
        ).append(
            	$('<option>', {'text':'Sort by Similarity', 'value': 3})
        ).on('change', function() {
        	  $list.jstree(true).sort($list.jstree(true).get_node('#'), 1);
        	  $list.jstree('close_all');
        	  if(open_all)
        		  $list.jstree('open_all');
        });
        $closeall.click(function(){ $list.jstree('close_all')});
        $expandall.click(function(){ $list.jstree('open_all')});
        
        $download.click(function(){
        	var wrapper = {'data':dataParsed, 'view': window.location.href }
        	$("<a />", {
        	    "download": "results.json",
        	    "href" : URL.createObjectURL(new Blob([JSON.stringify(wrapper, null, 2)], {type: "application/octet-stream"}))
        	  }).appendTo("body")
        	  .click(function() {
        	     $(this).remove()
        	  })[0].click()
        });
        
        $box = createBinarySelectionMenu(bins);
        console.log($box)
        $menu.add_menu_item('Filter by Source Binaries', [$box])
        $box.onselection = function(inverse_selected){
        	if(inverse_selected.length == 0){
        		 $list.jstree(true).show_all();
        	}else{
        		$($list.jstree().get_json($list, {
        	          flat: true
        	        })).each(function(index, value) {
        	          if(value.a_attr.lvl==2 && inverse_selected.has(value.a_attr.bid)){
        	        	  $list.jstree(true).hide_node(value);
        	          }else{
        	        	  $list.jstree(true).show_node(value);
        	          }
        	    });
        		root = $list.jstree(true).get_node('#').children[0];
        		$list.jstree(true).close_node(root);
        		$list.jstree(true).open_node(root);
        	}
        }
        $box.init()

    }


function CreateCloneGraph(graph, placeholderId, callback) {

    if(graph.nodes.length > 1500){
    	alert('Graph too large (>1500) nodes.');
    	return;
    }
        

    var color = d3.scale.category10();

    var zoom = d3.behavior.zoom()
            .scaleExtent([0.2, 10])
            .on("zoom", zoomed);

    var unzoom = d3.behavior.zoom()
            .scaleExtent([0.2, 10])
            .on("zoom", null);

    var mousedown_node = null;
    var mouseup_node = null;

    function zoomed() {
        container.attr("transform", "translate(" + d3.event.translate + ")scale(" + d3.event.scale + ")");
    }

    var force = d3.layout.force()
            .charge(-120)
            .linkDistance(30);
    // .linkStrength(function(link) {
    // return link.value;
    // });
    d3.select("#"+placeholderId).selectAll("*").remove();

    var svg = d3.select("#" + placeholderId)
            .append("svg")
            .attr('height', '100%')
            .attr('width', '100%')
            .append("g")
            .call(zoom);

// for filing the zoom event every where
    var rect = svg.append("rect")
            .attr('height', '100%')
            .attr('width', '100%')
            .style("fill", "none")
            .style("pointer-events", "all");

    var container = svg.append("g");

    force
            .nodes(graph.nodes)
            .links(graph.links)
            .start();

    var link = container.selectAll(".link")
            .data(graph.links)
            .enter().append("line")
            .attr("class", "link");

    var gnodes = container.selectAll(".node")
            .data(graph.nodes)
            .enter()
            .append('g')
            .attr("class", "node")
            .on("dblclick",
                    function (d) {
            			callback(svg, d);

                    })
            .on("mousedown",
                    function (d) {
                        svg.call(unzoom);
                        mousedown_node = d;

                    })
            .on("mousedrag",
                    function (d) {

                    })
            .on("mouseup",
                    function (d) {
                        if (mousedown_node) {
                            mouseup_node = d;
                            if (mouseup_node == mousedown_node) {
                                mousedown_node = null;
                                mouseup_node = null;
                                svg.call(zoom);
                            }
                        }
                    })
            .call(force.drag);

    var circles = gnodes.append("circle")
            .attr("r", function (d) {
                return 5;
            })
            .style("fill", function (d) {
                return color(d.binaryGroupID);
            });

    circles.append("title")
            .text(function (d) {
                return d.name;
            });

    gnodes.append("text")
            .attr("x", 12)
            .attr("dy", ".35em")
            .text(function (d) {
                return d.name;
            });

    force.on("tick", function () {
        link.attr("x1", function (d) {
            return d.source.x;
        })
                .attr("y1", function (d) {
                    return d.source.y;
                })
                .attr("x2", function (d) {
                    return d.target.x;
                })
                .attr("y2", function (d) {
                    return d.target.y;
                });

        gnodes.attr("transform", function (d) {
            return "translate(" + d.x + "," + d.y + ")";
        });
    });
    
    
    function resize() {
    	var wa = document.getElementById(placeholderId).offsetWidth;
    	var ha = document.getElementById(placeholderId).offsetHeight;
    	console.log([wa, ha]);
        svg.attr("width", wa).attr("height", ha);
        console.log([svg.attr("width"), svg.attr("height")])
        force.size([wa, ha]).resume();
      };
    
    resize();
    d3.select(window).on("resize", resize);
}

function drawLogicFlow(func, placeholderId) {
		console.log('drawing logic flow');
	
        var g = new dagreD3.graphlib.Graph({compound: true}).setGraph({
            //rankdir: "LR"
            // align:"UR",
            // ranker: "longest-path"
        });
        var t_nodes = func.nodes;
        var t_links = func.links;

        for (var i = 0; i < t_nodes.length; ++i) {
            var node = t_nodes[i];

            // address node
            g.setNode(node.logic.inputs.id,
                    {
                        label: node.logic.inputs.content.join("\n"),
                        style:"fill: white; font-weight: bold"
                    });

            g.setNode(node.logic.outputs.id,
                    {
                        label: node.logic.outputs.content.join("\n"),
                        style:"fill: white; font-weight: bold"
                    });

            // group node (cluster)
            var groupId = node.blockID + "_group";
            g.setNode(groupId, {label: node.name, clusterLabelPos: 'top', style: 'fill: #d3d7e8'});
            g.setParent(node.logic.inputs.id, groupId);
            g.setParent(node.logic.outputs.id, groupId);

            // logic nodes inside this cluster
            for (var j = 0; j < node.logic.nodes.length; ++j) {
                var logicNode = node.logic.nodes[j];
                g.setNode(logicNode.id,
                        {
                            label: logicNode.content.join("\n"),
						    style:"fill: white; font-weight: bold"
                        });
                g.setParent(logicNode.id, groupId);
            }

            // set links for the logic nodes:
            node.logic.links.forEach(function (link) {
                g.setEdge(link.source, link.target, {
                    label: "feed",
                    lineInterpolate: 'basis'
                });
            });
        }
        ;

        // add CFG links
        t_links.forEach(function (link) {
            g.setEdge(link.source + "_output_stage", link.target + "_input_stage", {label: "call"});
        });


        // Set some general styles
        g.nodes().forEach(function (v) {
            var node = g.node(v);
            // node.rx = node.ry = 5;
        });

        var svg = d3.select("#" + placeholderId).select("svg");

        var inner = svg.select("g");
        inner.selectAll("*").remove();
        var area = inner.append("g");

        // Create the renderer
        var render = new dagreD3.render();

        // Run the renderer. This is what draws the final graph.
        render(inner, g);

        var graphHeight = g.graph().height;
		var graphWidth = g.graph().width;
        var scale = 0.07;
		var svg_width = svg.node().getBoundingClientRect().width;
		var translate = [(svg_width - graphWidth * scale) / 2, 20];

        // set slider:
        var slider = $("#" + placeholderId + " input.slider")
                .slider({min: 0, max: 100})
                .data('slider');

        // Set up zoom support
        var zoom = d3.behavior.zoom().on("zoom", function () {

            translate = d3.event.translate;
            var top = d3.event.translate[1];
            scale = d3.event.scale;

            var slideVal = top / (graphHeight * scale - 800) * -100.0;
            slider.setValue(slideVal);
            inner.attr("transform", "translate(" + d3.event.translate + ")" +
                    "scale(" + d3.event.scale + ")");
        });
        svg.call(zoom);


        slider.on('slide', function (slideEvt) {
                    translate[1] = slider.getValue() / (-100.0) * (graphHeight * scale - 800);
                    //console.log(translate);
                    zoom
                            .translate(translate)
                            .scale(scale)
                            .event(svg);
                }
        );

        zoom.translate(translate).scale(scale).event(svg);


        // svg.attr('height', $(document).height() - 50 - 52);


        var gnodes = inner.selectAll(".node").on("dblclick",
                function (d) {

                })
                .on("mousedown",
                        function (d) {

                        })
                .on("mousedrag",
                        function (d) {

                        })
                .on("mouseup",
                        function (d) {
                            inner.selectAll("g.edgePath").style("stroke", "black");
                            inner.selectAll("g.edgePath").filter(function (index) {
                                return this.__data__.v === d;
                            }).style("stroke", "green");
                            inner.selectAll("g.edgePath").filter(function (index) {
                                return this.__data__.w == d;
                            }).style("stroke", "red");
                        });

//setup tool tips for links
        inner.selectAll("g.edgePath")
                .attr("title", function (v) {
                    var targ = v.w;
                    var node = g.node(targ);
                    return node.label;
                })
                .each(function (v) {
                    $(this).tipsy({
                        trigger: 'hover',
                        gravity: 'e',
                        follow: 'y',
                        opacity: 0.8, html: true
                    });
                });
	inner.selectAll("g.edgePath").style("stroke", "black");

 }


function drawFlow(func, placeholderId, cloneSets, code_key='srcCodes') {
	var clonePartColors = d3.scale.category10().range().concat(d3.scale.category20c().range());
    var g = new dagreD3.graphlib.Graph({multigraph: true}).setGraph({});
    var t_nodes = func.nodes;
    var t_links = func.links;

    for (var i = 0; i < t_nodes.length; ++i) {
        var node = t_nodes[i];
        g.setNode(node.blockID,
                {
                    label: node[code_key].join("\n"), 
					style:"fill: white; font-weight: bold",
					sea: node.sea
                });
    }

    t_links.forEach(function (link) {
        g.setEdge(link.source, link.target, {label: "call"});
    });

    // Set some general styles
    g.nodes().forEach(function (v) {
        var node = g.node(v);
        // node.rx = node.ry = 5;
    });

    var svg = d3.select("#" + placeholderId).select("svg")

    var inner = svg.select("g");
    inner.selectAll("*").remove();
    var area = inner.append("g");

    // Create the renderer
    var render = new dagreD3.render();

    // Run the renderer. This is what draws the final graph.
    render(inner, g);

    var graphHeight = g.graph().height;
	var graphWidth = g.graph().width;
    var scale = 0.3;
	var svg_width = svg.node().getBoundingClientRect().width;
	var translate = [(svg_width - graphWidth * scale) / 2, 20];
	var original_translate = translate;
	var original_scale = scale;

    // set slider:
    var slider = $("#" + placeholderId + " input.slider")
            .slider({min: 0, max: 100})
            .data('slider');

    // Set up zoom support
    var zoom = d3.behavior.zoom().on("zoom", function () {

        translate = d3.event.translate;
        var top = d3.event.translate[1];
        scale = d3.event.scale;

        var slideVal = top / (graphHeight * scale - 800) * -100.0;
        slider.setValue(slideVal);
        inner.attr("transform", "translate(" + d3.event.translate + ")" +
                "scale(" + d3.event.scale + ")");
    });
    svg.call(zoom).on("dblclick.zoom", null);


    slider.on('slide', function (slideEvt) {
                translate[1] = slider.getValue() / (-100.0) * (graphHeight * scale - 800);
                // console.log(translate);
                zoom
                        .translate(translate)
                        .scale(scale)
                        .event(svg);
            }
    );

    zoom.translate(translate).scale(scale).event(svg);

    // svg.attr('height', $(document).height() - 50 - 52);


    var gnodes = inner.selectAll(".node").on("dblclick",
            function (d, e) {
    			if(typeof send_msg != 'undefined'){
    				var node = g.node(d);
    				var addr = parseInt(node.sea);
    				var addr = "0x" + addr.toString(16);
    				send_msg("jumpto("+addr +")");
    			}
            })
            .on("mousedown",
                    function (d) {

                    })
            .on("mousedrag",
                    function (d) {

                    })
            .on("mouseup",
                    function (d) {


                    });
    inner.selectAll(".node").attr("title", function (d) {
                    	if(typeof send_msg != 'undefined'){
	        				return "Double-click to jump in IDA Pro"
                    	}
                    }).each(function(v) { $(this).tipsy({ gravity: "w", opacity: 1, html: true }); });

// setup tool tips for links
    /*
	 * inner.selectAll("g.edgePath") .attr("title", function (v) { var targ =
	 * v.w; var node = g.node(targ); return node.label; }) .each(function (v) {
	 * $(this).tipsy({ trigger: 'hover', gravity: 'e', follow: 'y', opacity:
	 * 0.8, html: true }); });
	 */

// highlight the link when mouse hover
    inner.selectAll("g.edgePath").style("stroke", "black");
    inner.selectAll("g.edgePath").on("mouseover", function (d) {
        inner.selectAll("g.edgePath").style("stroke", "black");
        d3.select(this).style("stroke", "green");
    });

// draw clone boundaries
    var lineFunction = d3.svg.line()
            .x(function (d) {
                return d.x;
            })
            .y(function (d) {
                return d.y;
            })
            .interpolate("monotone");

    var color = 'white';
    var index = 0;
    for (var j = 0; j < cloneSets.length; ++j) {
        var cloneSet = cloneSets[j];
        color = clonePartColors[index % clonePartColors.length];
        var convexHullSource = new ConvexHullGrahamScan();
        for (var k = 0; k < cloneSet.length; ++k) {
            var clonePair = cloneSet[k];
            inner.selectAll("g.node").each(function (i, d) {
                if ((placeholderId=='chartSource'&&i == clonePair._1) || (placeholderId=='chartTarget'&&i == clonePair._2)) {
                    var m = this.transform.animVal[0]['matrix'];
                    var re = this.children[0];

                    var x1 = re.x.animVal.value + m['e'];
                    var y1 = re.y.animVal.value + m['f'];
                    convexHullSource.addPoint(x1 - 5, y1 - 5);
                    convexHullSource.addPoint(x1 - 5, y1 + re.height.animVal.value + 5);
                    convexHullSource.addPoint(x1 + re.width.animVal.value + 5, y1 + re.height.animVal.value + 5);
                    convexHullSource.addPoint(x1 + re.width.animVal.value + 5, y1 - 5);
                }
            });
        }
        var hullPointsSource = convexHullSource.getHull();
        hullPointsSource.push(hullPointsSource[0]);
        area.append("path")
                .attr("d", lineFunction(hullPointsSource))
                .attr("stroke", "blue")
                .attr("stroke-width", 2)
                .attr("fill", color)
                .style("fill-opacity", 0.3).style("stroke-dasharray", ("3, 3"));
        index++;
    }
    
    reset = function(){
    	 svg
         .transition()
         .duration(1000) // milliseconds
         .call(zoom.translate(original_translate).scale(original_scale).event);
    }
    search_call_backs.push(reset);
    return reset;
}

function normalize(line){
    return line.replace(/\s{2,}/g, ' ').replace(/;[\s\S]*/g, '') + "\r\n";
}

function isVexCode(p_func, code_key='srcCodes'){
	if(p_func.nodes.length > 0 && p_func.nodes[0][code_key].length > 0)
		return p_func.nodes[0][code_key][0].includes('SIMPLIFIED VEX CODE');
	return false;
}

function drawTextDiff(p_a, p_b, titleId, tableId, left_prefix, right_prefix, normalize_opr=false, code_key='srcCodes') {
	
	var a_isVex = isVexCode(p_a, code_key);
	var b_isVex = isVexCode(p_b, code_key);
	
    var code_a = "", code_b = "";
    var addr_a = [], addr_b = [];
    var addr_ind_a = 0, addr_ind_b = 0;
    for (var i = 0; i < p_a.nodes.length; ++i) {
        for (var j = 0; j < p_a.nodes[i][code_key].length; ++j) {
            var parts = p_a.nodes[i][code_key][j].split(' ');
            if(parts.length < 2)
            	continue;
            addr_a.push(parts[0]);
            if(normalize_opr && !a_isVex){
            	normalizer.normalize_opr(parts[1]);
            }
            code_a += normalize(parts.slice(1, parts.length).join(' ')) + "\r\n";
        }
    }

    for (var i = 0; i < p_b.nodes.length; ++i) {
        for (var j = 0; j < p_b.nodes[i][code_key].length; ++j) {
            var parts = p_b.nodes[i][code_key][j].split(' ');
            if(parts.length < 2)
            	continue;
            addr_b.push(parts[0]);
            if(normalize_opr && !b_isVex)
            	normalizer.normalize_opr(parts[1]);
            code_b += normalize(parts.slice(1, parts.length).join(' ')) + "\r\n";
        }
    }

    var cache = [];
    var index = -1;
    var diff = JsDiff.diffTrimmedLines(code_a, code_b);
    $("#"+tableId).find("tr").remove();
    var tbl = $('#' + tableId + ' > tbody:last');
    for (var i = 0; i < diff.length; i++) {
        // put remove ahead e.g.
        // rm rm rm rm add add add ...
        if (diff[i].added && diff[i + 1] && diff[i + 1].removed) {
            var swap = diff[i];
            diff[i] = diff[i + 1];
            diff[i + 1] = swap;
        }

        var lines = diff[i].value.match(/[^\r\n]+/g);
        if (lines == null)
            continue;
        for (var j = 0; j < lines.length; ++j) {
            var line = lines[j];
            if (diff[i].removed) {
                var $newRow = $('<tr>');
                $newRow.append($('<td class=\'diff-line-num\'>')
                		.attr('id', left_prefix+addr_a[addr_ind_a])
                		.data('prefix', left_prefix)
                		.data('func', p_a)
                		.append(addr_a[addr_ind_a]).append($('<span class=\'commenter\'>').append('+')));
                addr_ind_a++;
                var parts = line.split(' ');
                if(!a_isVex){
	                $newRow.append($('<td class=\'diff-line-content remove\'>').append('-').append(
	                                $('<span class="m">').append(parts[0])
	                        ).append(' ').append(
	                                $('<span class="o">').append(parts.slice(1, parts.length).join(' '))
	                        )
	                );
                }else{
                	$newRow.append($('<td class=\'diff-line-content remove\'>').append('-').append(
	                                $('<span class="o">').append(parts.slice(0, parts.length).join(' '))
	                        )
	                );
                }
                cache.push($newRow);
                if (index == -1)
                    index = 0;
            } else if (diff[i].added) {
                if (index != -1 && index < cache.length) {
                    cache[index].append($('<td class=\'diff-line-num\'>')
                    		.attr('id', right_prefix+addr_b[addr_ind_b])
                    		.data('prefix', right_prefix)
                    		.data('func', p_b)
                    		.append(addr_b[addr_ind_b]).append($('<span class=\'commenter\'>').append('+')));
                    addr_ind_b++
                    var parts = line.split(' ');
                    if(!b_isVex){
	                    cache[index].append($('<td class=\'diff-line-content add\'>').append('+').append(
	                                    $('<span class="m">').append(parts[0])
	                            ).append(' ').append(
	                                    $('<span class="o">').append(parts.slice(1, parts.length).join(' '))
	                            )
	                    );
                    }else{
                    	cache[index].append($('<td class=\'diff-line-content add\'>').append('+').append(
	                                    $('<span class="o">').append(parts.slice(0, parts.length).join(' '))
	                            )
	                    );
                    }
                    index++;
                } else {
                    if (cache.length > 0) {
                        for (var k = 0; k < cache.length; ++k) {
                            tbl.append(cache[k]);
                        }
                        cache = [];
                        index = -1;
                    }
                    var $newRow = $('<tr>');
                    $newRow.append($('<td class=\'diff-line-num empty\'>'));
                    $newRow.append($('<td class=\'diff-line-content empty\'>'));
                    $newRow.append($('<td class=\'diff-line-num\'>')
                    		.attr('id', right_prefix+addr_b[addr_ind_b])
                    		.data('prefix', right_prefix)
                    		.data('func', p_b)
                    		.append(addr_b[addr_ind_b]).append($('<span class=\'commenter\'>').append('+')));
                    addr_ind_b++;
                    var parts = line.split(' ');
                    if(!b_isVex){
	                    $newRow.append($('<td class=\'diff-line-content add\'>').append('+').append(
	                                    $('<span class="m">').append(parts[0])
	                            ).append(' ').append(
	                                    $('<span class="o">').append(parts.slice(1, parts.length).join(' '))
	                            )
	                    );
                    }else{
                     	$newRow.append($('<td class=\'diff-line-content add\'>').append('+').append(
	                                    $('<span class="o">').append(parts.slice(0, parts.length).join(' '))
	                            )
	                    );
                    }
                    tbl.append($newRow)
                }
            } else {
                if (cache.length > 0) {
                    for (var k = 0; k < cache.length; ++k) {
                        if (cache[k].children().length == 2) {
                            cache[k].append($('<td class=\'diff-line-num empty\'>'));
                            cache[k].append($('<td class=\'diff-line-content empty\'>'));
                        }
                        tbl.append(cache[k]);
                    }
                    cache = [];
                    index = -1;
                }
                var $newRow = $('<tr>');
                var parts = line.split(' ');
                $newRow.append($('<td class=\'diff-line-num\'>')
                		.attr('id', left_prefix+addr_a[addr_ind_a])
                		.data('prefix', left_prefix)
                    	.data('func', p_a)
                		.append(addr_a[addr_ind_a]).append($('<span class=\'commenter\'>').append('+')));
                addr_ind_a++;
                if(!a_isVex){
	                $newRow.append($('<td class=\'diff-line-content\'>').append('&nbsp;').append(
	                                $('<span class="m">').append(parts[0])
	                        ).append(' ').append(
	                                $('<span class="o">').append(parts.slice(1, parts.length).join(' '))
	                        )
	                );
                }else{
                	$newRow.append($('<td class=\'diff-line-content\'>').append('&nbsp;').append(
	                                $('<span class="o">').append(parts.slice(0, parts.length).join(' '))
	                        )
	                );
                }
                $newRow.append($('<td class=\'diff-line-num\'>')
                		.data('prefix', right_prefix)
                    	.data('func', p_b)
                		.attr('id', right_prefix+addr_b[addr_ind_b])
                		.append(addr_b[addr_ind_b]).append($('<span class=\'commenter\'>').append('+')));
                addr_ind_b++;
                if(!b_isVex){
	                $newRow.append($('<td class=\'diff-line-content\'>').append('&nbsp;').append(
	                                $('<span class="m">').append(parts[0])
	                        ).append(' ').append(
	                                $('<span class="o">').append(parts.slice(1, parts.length).join(' '))
	                        )
	                );
                }else{
                	$newRow.append($('<td class=\'diff-line-content\'>').append('&nbsp;').append(
	                                $('<span class="o">').append(parts.slice(0, parts.length).join(' '))
	                        )
	                );
                }
                tbl.append($newRow);
            }
        }
    }
    $('.diff-line-num').hover(
            function () {
                $(this).find('span.commenter').addClass('selected');
            }, function () {
                $(this).find('span.commenter').removeClass('selected');
            }
    );
    if (cache.length > 0) {
        for (var k = 0; k < cache.length; ++k) {
            if (cache[k].children().length == 2) {
                cache[k].append($('<td class=\'diff-line-num empty\'>'));
                cache[k].append($('<td class=\'diff-line-content empty\'>'));
            }
            tbl.append(cache[k]);
        }
        cache = [];
        index = -1;
    }
}

function initForm(url){
	$('span.commenter').click(function(){
		var $rd = $(this).parent();
		if($rd.parent().next().hasClass('comForm')){
			$rd.parent().next().remove();
            return;
        }
		var $form = createFormSingle(url, $rd.text().replace('+', ''), $rd.data('func').functionId, null, $rd.data('prefix'))
		$form.insertAfter($rd.parent());
	});
}

all_cm_types = new Set(['anterior', 'posterior', 'regular', 'repeatable']);

function plotCommentsWithPrefix(url, fun, prefix, type_filters=all_cm_types){
	$.get(url, {
		fid: fun.functionId
	}, function(data){
		$.each(data, function(ind, ent){
            var $row = $('#'+prefix+ent.functionOffset);
            if (!type_filters.has(ent.type))
            	return;
            var $cmbox = createCommentRowSingle(ent, url, prefix);
            $cmbox.insertAfter($row.parent());
        });
	});
}

function createCommentRowSingle(cm, url, prefix){
    var $tr = $('<tr class=\"cmrow\">');
    if(prefix =='r-'){
    	$tr = $tr.append( $('<td class=\"diff-line-num empty\">'));
    	$tr = $tr.append( $('<td class=\"diff-line-content empty\">'));
    }
    $tr.append(
            $('<td colspan=\"2\">')
                    .append($('<span class=\"pull-right delete\">')
                            .append($('<i class=\"fa fa-times-circle\">'))
                            .click(function() {
                                var $sp = $(this);
                                var data = {
                                		functionId: cm.functionId,
                                		functionOffset: cm.functionOffset,
                                		date: cm.date,
                                		comment:""};
                                $.post(url,
                                    data,
                                    function (data) {
                                		if(data.error){
                                			alert(data.error);
                                			return;
                                		}
                                		$sp.parent().parent().parent().remove();
                                    }
                                );
                            })
            )
                    .append($('<span class=\"pull-right delete\">')
                            .append($('<i class=\"fa fa-edit\">'))
                            .click(function() {
                            	var $btn = $(this);
                                var $crow = $btn.parent().parent();
                                $form = createFormSingle(
                                		url, cm.functionOffset, cm.functionId, cm, prefix);
                                $form.insertAfter($crow);
                                $crow.remove();
                            })
            )
                    .append($('<div>').addClass('cmbox').addClass('cmbox-' + cm.type)
                            .append(markdown.toHTML( cm.comment ))
            )
    );
    if(prefix =='l-'){
    	$tr = $tr.append( $('<td class=\"diff-line-num empty\">'));
    	$tr = $tr.append( $('<td class=\"diff-line-content empty\">'));
    }
    return $tr;
}

function createFormSingle(url, addr, funId, comObj, prefix) {
    var $form = $('<tr class=\"comForm\">');
    if(prefix =='r-'){
    	$form = $form.append( $('<td class=\"diff-line-num empty\">'));
    	$form = $form.append( $('<td class=\"diff-line-content empty\">'));
    }
    $form.append(
            $('<td colspan=\"2\">').append(
                    $('<div>')
                            .append($('<textarea name=\"content\" data-height=\"200\" rows=\"10\" style=\"width:100%\">'))
                            .append($('<button class=\"btn-info btn-sm btn pull-right\" style="margin:2px">').on('click', function (event) {
                                var cm = $form.find('textarea').val();
                                var data = {
                                		functionId: funId,
                                		functionOffset: addr,
                                		date: comObj == null ? "" : comObj.date,
                                		comment:cm};
                                $.post(
                                		url,
                                        data,
                                    function (dataParsed) {
                                        if (dataParsed) {
                                        	
                                        	if(dataParsed.error && dataParsed.error.contains('Failed')){
                                        		alert(dataParsed.error);
                                        		return;
                                        	}else if(dataParsed.error){
                                        		// index new func;
                                        		if (confirm('Failed to persist this comment. This function is not indexed in the database. Do you want to index it now?')) {
                                                	external.IndexFunc(currentFun, function(msg){alert(msg)});
                                        		}
                                        	}
                                        	dataParsed = dataParsed.result;
                                        	
                                            var $row = $form.prev();
                                            $form.remove();
                                            createCommentRowSingle(dataParsed, url, prefix, addr).insertAfter($row);
                                        }
                                    }
                                );
                            }).append('submit'))
                            .append($('<button class=\"btn-danger btn-sm btn pull-right\" style="margin:2px">').on('click', function (event) {
                                if(comObj!=null){
                                    var $row = $form.prev();
                                    createCommentRowSingle(comObj, url, prefix, addr).insertAfter($row);
                                }
                                $form.remove();
                            }).append('close'))
                            .append($('<span class=\"pull-left\" style="margin:2px;font-size: 12px;color: rgb(170, 170, 170);">').append('Markdown Supported'))
            )
    );
    var $editArea = $form.find('textarea');
    if(comObj != null)
        $editArea.val(toMarkdown(comObj.comment));
    $editArea.markdown({autofocus: true, savable: false, iconlibrary: 'fa', fullscreen: true});
    if(prefix =='l-'){
    	$form = $form.append( $('<td class=\"diff-line-num empty\">'));
    	$form = $form.append( $('<td class=\"diff-line-content empty\">'));
    }
    return $form;
}

function plotCommentSingle(url, func){
	plotCommentsWithPrefix(url, func, '');
}

function drawText(p_a, titleId, tableId, code_key='srcCodes'){
	 $('#' + titleId).html(
			 p_a.functionName + "(#" + p_a.functionId.toString(16) + ")@" + p_a.binaryName + "(#" + p_a.binaryId.toString(16)
	            + ")");

	    var code_a = [];
	    var addr_a = [];
	    var addr_ind_a = 0;
	    for (var i = 0; i < p_a.nodes.length; ++i) {
	        for (var j = 0; j < p_a.nodes[i][code_key].length; ++j) {
	            var parts = p_a.nodes[i][code_key][j].split(' ');
	            addr_a.push(parts[0]);
	            code_a.push(p_a.nodes[i][code_key][j]);
	        }
	    }

	    $("#"+tableId).find("tr").remove();
	    var tbl = $('#' + tableId + ' > tbody:last');
	    for (var i = 0; i < code_a.length; i++) {
	    	var parts = code_a[i].split(' ');
	    	var $newRow = $('<tr>');
	    	$newRow.append($('<td class=\'diff-line-num\'>')
            		.attr('id', addr_a[addr_ind_a])
            		.data('prefix', '')
                	.data('func', p_a)
            		.append(addr_a[addr_ind_a]).append($('<span class=\'commenter\'>').append('+')));
            addr_ind_a++;
            $newRow.append($('<td class=\'diff-line-content\'>').append('&nbsp;').append(
                    $('<span class="m">').append(parts[1])
            ).append(' ').append(
                    $('<span class="o">').append(parts.slice(2, parts.length).join(' '))
            ));
            tbl.append($newRow);
	    }
	    $('.diff-line-num').hover(
	            function () {
	                $(this).find('span.commenter').addClass('selected');
	            }, function () {
	                $(this).find('span.commenter').removeClass('selected');
	            }
	    );
}

function createDropDownMenu($menubar, cls="pull-right"){
	$ul = $('<ul>', {'class':"dropdown-menu dropdown-menu-right", 'style':'color:black; width:300px'});
	$menu = $('<div>', {'class':"dropdown " + cls, 'style':'margin-left:30px'}).append(
			$('<li class="dropdown">').append(
					$('<a class="dropdown-toggle" data-toggle="dropdown" style="cursor:pointer">').append(
							$('<i class="material-icons">settings</i>')
					)
			).append(
					$ul
			)
	);
	$menubar.append($menu);
	
	$menu.add_menu_item = function(label, items){
		$div = $('<div>', {'class':'row', 'style':'margin-left:15px;margin-right:15px'});
		$ul.append(
				$('<li>').append($div.append($('<h6>').text(label)))
		   ).click(function(e) {
				  e.stopPropagation();
				  });
		$.each(items, function(i,e){$div.append(e)})
	}
	
	$menu.complete = function(){
		$.material.init();
	}
	
	return $menu
}

function createCommentDropDownMenu(hide_parent=false){
	items = [];
	var not_selected = new Set(); 
	onchanged = function(){
		$("input.cmm-chk").each(function(){
			 var input = $(this);
			 if(!input.context.checked){
				 not_selected.add(input.val())
				 if(hide_parent)
					 $('.cmbox.cmbox-'+input.val()).parent().hide();
				 else
					 $('.cmbox.cmbox-'+input.val()).hide();
			 }else{
				 not_selected.delete(input.val())
				 if(hide_parent)
					 $('.cmbox.cmbox-'+input.val()).parent().show();
				 else
				 $('.cmbox.cmbox-'+input.val()).show();
			 }
		});
		console.log(not_selected);
	}
	
		
	items.push($('<div>', {'class':'togglebutton cmbox-anterior'}).append(
							$('<label>', {'style':'color:grey'}).append(
									$('<input>', {'class':"checkbox cmm-chk", 'type':"checkbox", 'checked':'true', 'value':'anterior'}).change(onchanged)
							).append(document.createTextNode('Anterior Comments'))
					));		
			
					items.push($('<div>', {'class':'togglebutton cmbox-posterior'}).append(
							$('<label>', {'style':'color:grey'}).append(
									$('<input>', {'class':"checkbox cmm-chk", 'type':"checkbox", 'checked':'true', 'value':'posterior'}).change(onchanged)
							).append(document.createTextNode('Posterior Comments'))
					));		
			
					items.push($('<div>', {'class':'togglebutton cmbox-regular'}).append(
							$('<label>', {'style':'color:grey'}).append(
									$('<input>', {'class':"checkbox cmm-chk", 'type':"checkbox", 'checked':'true', 'value':'regular'}).change(onchanged)
							).append(document.createTextNode('Regular Comments'))
					));		
			
					items.push($('<div>', {'class':'togglebutton cmbox-repeatable'}).append(
							$('<label>', {'style':'color:grey'}).append(
									$('<input>', {'class':"checkbox cmm-chk", 'type':"checkbox", 'checked':'true', 'value':'repeatable'}).change(onchanged)
							).append(document.createTextNode('Repeatable Comments'))
					));		
			


	return {items: items, not_selected: not_selected};
}

function createNormalizationSettingMenu(onchanged){
	
	
	$div = $('<div>');
	$select = $('<select>', {'class':"form-control", 'style':"width: 100%; margin-top: 0; position: relative; top: 0;"});
	$chk = $('<input>', {'class':"checkbox", 'type':"checkbox"});
	$.each(['arm', 'metapc', 'ppc'], function(i,e){
		$select.append($('<option>', {'value':e}).text(e))
	});
	items = [];
	items.push($div.append(
			$('<div>', {'class':'togglebutton'}).append(
					$('<label>', {'style':'color:black'}).append($chk
					).append(document.createTextNode('Normalize Operator'))
	).append(
			$('<div>', {'class':'form-group', 'style':'margin:0'}).append(
					$select
			)
	)));
	$chk.change(function(){
		onchanged($chk.prop('checked'), $select.val())
	})
	return items;
}


var normalizer = undefined
function createNormalizer(res_url, type){
	
	if(normalizer != undefined)
		return;
	var obj_name = 'asm-' + type
	var retrievedObject = localStorage.getItem('obj_name');
	
	function init(){
		normalizer = retrievedObject;
		normalizer.normalize_opr = function(opr){
			var no_suffix = normalizer.operationMap[opr.toUpperCase()];
			if(no_suffix != undefined)
				return no_suffix;
			return opr;
		}
	}
	
	if(retrievedObject == undefined){
		$.ajax({
			type : 'GET',
			dataType : 'json',
			url : res_url,
			data:{
				arch: type
			},
			success : function(data) {
				if(data.error){
					dmas_alert(data);
				}else{
					retrievedObject = data;
					localStorage.setItem(obj_name, JSON.stringify(data));
					init();
				}
			}
		});
	}else{
		init();
	}
}

function createBinarySelectionMenu(bins){
	var not_selected = new Set(); 
	var colorF = d3.scale.category10();

	var $holder = $('<div>');
	$holder.onselection = function(){}
	onchanged = function(){
		$holder.find("input").each(function(){
			 var input = $(this);
			 if(!input.context.checked){
				 not_selected.add(input.val());
			 }else{
				 not_selected.delete(input.val());
			 }
		});
		console.log(not_selected);
		$holder.onselection(not_selected);
	}
	
	$.each(bins, function(k, v) {
		var clr = colorF(k) ;
		$div = $('<div>', {
			'class' : 'togglebutton'
		}).append(
				$('<label>', {
					'style' : 'color:grey'
				}).append($('<input>', {
					'class' : "checkbox",
					'type' : "checkbox",
					'checked' : 'true',
					'value' : k
				}).change(onchanged)).append(
						document.createTextNode(v)))
						.css('background-color', clr+ "20")
						.css('border-left', 'solid 3px '+clr)
		$holder.append($div);
	});
	$holder.init = function (){
		$.material.init();
	}
	return $holder;
}
