/*******************************************************************************
 * Copyright 2015 McGill University. All rights reserved.                       
 *                                                                               
 * Unless required by applicable law or agreed to in writing, the software      
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF      
 * ANY KIND, either express or implied.                                         
 *******************************************************************************/
var wa = screen.availWidth;

var margin = {top: -5, right: -5, bottom: -5, left: -5},
    width = wa - margin.left - margin.right,
    height = 500 - margin.top - margin.bottom;

var color = d3.scale.category20();

var zoom = d3.behavior.zoom()
    .scaleExtent([1, 10])
    .on("zoom", zoomed);

var unzoom = d3.behavior.zoom()
    .scaleExtent([1, 10])
    .on("zoom", null);

var mousedown_node = null;
var mouseup_node = null;

function zoomed() {
  container.attr("transform", "translate(" + d3.event.translate + ")scale(" + d3.event.scale + ")");
}

var force = d3.layout.force()
    .charge(-120)
    .linkDistance(30)
    .size([width, height]);

var svg = d3.select("body")
  .append("svg")
    .attr("width", width)
    .attr("height", height)
  .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.right + ")")
    .call(zoom);

// for file the zoom event every where
var rect = svg.append("rect")
    .attr("width", width)
    .attr("height", height)
    .style("fill", "none")
    .style("pointer-events", "all");

var container = svg.append("g");

d3.json("miserables.json", function(error, graph) {
  force
      .nodes(graph.nodes)
      .links(graph.links)
      .start();

  var link = container.selectAll(".link")
      .data(graph.links)
    .enter().append("line")
      .attr("class", "link")
      .style("stroke-width", function(d) { return Math.sqrt(d.value); });

  var node = container.selectAll(".node")
      .data(graph.nodes)
    .enter().append("circle")
      .attr("class", "node")
      .attr("r", 5)
      .style("fill", function(d) { return color(d.group); })
      .on("mousedown", 
        function(d) { 
          svg.call(unzoom);
          mousedown_node = d;
        })
      .on("mousedrag",
        function(d) {
          
        })
      .on("mouseup", 
        function(d) { 
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

  node.append("title")
      .text(function(d) { return d.name; });

  force.on("tick", function() {
    link.attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; });

    node.attr("cx", function(d) { return d.x; })
        .attr("cy", function(d) { return d.y; });
  });
});