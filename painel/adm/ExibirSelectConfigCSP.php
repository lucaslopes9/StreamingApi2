<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspConfig');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspConfig = $VerificarAcesso[0];
 
if($ServidorcspConfig == 'S'){
	
$id = isset($_POST['id']) ? $_POST['id'] : '';

if($id == "S"){
	
$SQL = "SELECT ip FROM painel_config";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();
	
echo "
	<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['IPper']."</label>
                            <div class=\"col-md-9\">
							<textarea rows=\"5\" class=\"validate[required] form-control\" id=\"EditarIP\" name=\"EditarIP\">".$Ln['ip']."</textarea>
                            </div>
                        </div>
";
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>