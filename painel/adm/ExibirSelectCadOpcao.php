<?php
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;

$OpcaoForm = empty($_POST['OpcaoForm']) ? "" : $_POST['OpcaoForm'];
$CadUser = empty($_POST['CadUser']) ? "" : $_POST['CadUser'];

if($OpcaoForm == "T"){
	echo "<h4>".$_TRA['Operadora']."</h4>
          <div class=\"form-group\">
          	<div class=\"col-md-12\">                                        
            	<select class=\"form-control select\" id=\"Operadora\" name=\"Operadora\">
				".SelectOperadora($CadUser)."
                </select>
            </div>
          </div>";
}
else{
	echo "<h4>Cupom</h4>
	<div class=\"form-group\">
    	<div class=\"col-md-12\">
        	<input name=\"cupom\" id=\"cupom\" type=\"text\" class=\"form-control\" placeholder=\"Insira seu cupom!\"/>
        </div>
    </div>
    ";
}
?>

<script type='text/javascript' src='js/plugins/bootstrap/bootstrap-select.js'></script>
<script type="text/javascript" src="js/plugins.js"></script>
