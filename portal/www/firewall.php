<!DOCTYPE html>
<html>
<head>
	<!-- meta info -->
    <meta charset="utf-8" />
    <meta name="description" content="Firewall page" />
    <meta name="keywords" content="Apply" />
    <meta name="author" content="Darcy" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" type="text/css" href="{{ url_for('static', filename='css/main.css') }}">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
	<script src="script.js"></script>
</head>
<body>
<h2>WAF Portal</h2>

	<nav class="nav1"><!-- nav menu -->
		<div> Health Status&#128578 </div> 
		<a href="serverstatus.html">Server Status</a>
		<a href="logsearch.html">Log Search</a>
		<a href="firewall.html">Firewall Settings</a>
		<div class="nav2">
			<a href="logsearch.php">Edit user</a>
			<a href="{{url_for('logout')}}">Logout</a>
		</div>
	</nav>

	<div class="rendered-form">
		<form id="confirm" action="" method="post"></form> <!-- put database link in action -->
		<fieldset>
			<div>
				<h1 >Firewall settings</h1></div>
			</div>
				<h2 >IP Settings</h2></div>
			<div>
				<label for="select2" class="formbuilder-select-label">Block by country</label>
				<select class="form-control" name="select2">
					<option value="option-0" selected="true" >select</option>
					<option value="option-1" >Australia</option>
					<option value="option-2" >Venezuela</option>
					<option value="option-3" >Sweden</option>
				</select>
			</div>
			<div>
				<label for="text3" class="formbuilder-text-label">Block by IP address</label>
				<input type="text" class="form-control" name="text3" access="false">
			</div>
			
		</fieldset>
		<div class="topnav">
			<div class="search-container">
				<form action="/action_page.php">
				  <input id="myInput" type="text" placeholder="Search.." onkeyup= "searchFunction()" name="search">
				  <button type="submit"><i class="fa fa-search"></i></button>
				</form>
			</div>
		</div>
		<fieldset>
			<table style="undefined;table-layout: fixed; width: 600px">
			<colgroup>
			<col style="width: 77px">
			<col style="width: 200px">
			<col style="width: 200px">
			</colgroup>
			<thead>
			  <tr>
				<th>ID</th>
				<th>IP Address</th>
			  </tr>
			</thead>
			<tbody>
				<?php
				$mongoClient = new MongoClient();
				
				$db = $mongoClient -> selectDB($dbCollection);//TODO: Add Database name
				$dbCollection = $db->selectCollection($WAFFilters);
				$tableResults = $dbCollection->find();

				foreach ($tableResults as $tableResult) {
					$ID = $tableResult["__id"];
					$IP = $tableResut["IP Address"];


					$resultContent = [];
					
					$resultContent[0] = $ID;
					$resultContent[1] = $IP;

					echo "<tr>";
					foreach ($resultContent as $result) {
						echo "<td>"
						$resultText = "";
						for ($i=0; $i < $result.count(); $i++) { 
							$resultText .= $result; //Append result to set string
							if ($i != $result.count() - 1) {
								$result.text .= " ";
							};
						};
						echo $resultText;
						echo "</td>"
					}
					echo "</tr>";

				}
				?>
			  <tr>
				<td>1</td>
				<td>128.0.0.1/27</td>
			  </tr>
			  <tr>
				<td>2</td>
				<td>192.168.0.1/24</td>
			  </tr>
			  <tr>
				<td>3</td>
				<td>10.0.0.1/16</td>
			  </tr>
			</tbody>
			</table>
			<table style="undefined;table-layout: fixed; width: 600px">
				<colgroup>
				<col style="width: 77px">
				<col style="width: 200px">
				<col style="width: 200px">
				</colgroup>
				<thead>
				  <tr>
					<th>ID</th>
					<th>Geo location</th>
				  </tr>
				</thead>
				<tbody>
				<?php
				$mongoClient = new MongoClient();
				
				$db = $mongoClient -> selectDB($dbCollection);//TODO: Add Database name
				$dbCollection = $db->selectCollection($WAFFilters);
				$tableResults = $dbCollection->find();

				foreach ($tableResults as $tableResult) {
					$ID = $tableResult["__id"];
					$IP = $tableResut["Location"];


					$resultContent = [];
					
					$resultContent[0] = $ID;
					$resultContent[1] = $Location;

					echo "<tr>";
					foreach ($resultContent as $result) {
						echo "<td>"
						$resultText = "";
						for ($i=0; $i < $result.count(); $i++) { 
							$resultText .= $result; //Append result to set string
							if ($i != $result.count() - 1) {
								$result.text .= " ";
							};
						};
						echo $resultText;
						echo "</td>"
					}
					echo "</tr>";

				}
				?>
				  <tr>
					<td>1</td>
					<td>Germany</td>
				  </tr>
				  <tr>
					<td>2</td>
					<td>Sweden</td>
				  </tr>
				  <tr>
					<td>3</td>
					<td>Australia</td>
				  </tr>
				</tbody>
				</table>
		</fieldset>
		<div>
			<button type="reset" class="btn" name="button1" access="false" id="reset" style="default">Reset</button>
		</div>
		<div>
			<button type="submit" class="btn" name="button2" access="false" id="submit" style="default">Submit</button>
		</div>		
		</form>
	</div>
</body>
</html>