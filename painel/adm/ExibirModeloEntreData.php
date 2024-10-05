<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('OpcoesCircular');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAdmin);
$OpcoesCircular = $VerificarAcesso[0];
 
if($OpcoesCircular == 'S'){
	
$DataAtual = date('d/m/Y',time());
$id = (isset($_POST['id'])) ? $_POST['id'] : '';

if($id == "S"){
	
echo "

						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Data']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<div class=\"input-group\">
                                    	<input type=\"text\" class=\"form-control EntreDatasPicker\" id=\"DataInicio\" name=\"DataInicio\" value=\"".$DataAtual."\"/>
                                        <span class=\"input-group-addon add-on\"> - </span>
                                        <input type=\"text\" class=\"form-control EntreDatasPicker\" id=\"DataFinal\" name=\"DataFinal\" value=\"".$DataAtual."\"/>
                                    </div>
                                </div>
                        </div>

";
}

?>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-datepicker.js"></script>
<script type="text/javascript" src="js/plugins/bootstrap/locales/bootstrap-datepicker<?php echo Idioma(2); ?>.js"></script>

<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>