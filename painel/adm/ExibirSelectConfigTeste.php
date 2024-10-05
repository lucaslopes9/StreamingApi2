<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$id = isset($_POST['id']) ? $_POST['id'] : '';

if($id == "S"){
	
echo "
	<div class=\"form-group\">
    		<label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
        	<div class=\"col-md-9\">
           		<input id=\"EditarEmail\" name=\"EditarEmail\" type=\"text\" class=\"validate[custom[email]] form-control\">
            </div>
    </div>
";

}
}else{
	echo Redirecionar('login.php');
}	
?>