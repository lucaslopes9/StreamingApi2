<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){
	
$ColunaAcesso = array('ServidorcspInfo');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspInfo = $VerificarAcesso[0];

if($ServidorcspInfo == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
$SQL = "SELECT senha, deskeys, ip FROM painel_config";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();

if(substr_count($Ln['ip'], ";") > 0){
	$ippermitido = str_replace(";","<br>",$Ln['ip']);
}
else{
	$ippermitido = $Ln['ip'];
}

$SQLCSP = "SELECT id, nome, url, porta, usuario, senha, protocolo, block FROM painel WHERE id = :id";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->bindParam(':id', $id, PDO::PARAM_INT);
$SQLCSP->execute();
$LnCSP = $SQLCSP->fetch();
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$LnCSP['nome']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">Crontab</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							*/1 * * * * curl --request GET '".UrlAtual()."crontab.php'
							</p>
                            </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['link']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".UrlAtual()."xml.php?key=".md5($Ln['senha'])."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ipul']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$LnCSP['url']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$LnCSP['porta']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$LnCSP['usuario']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$LnCSP['senha']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Deskeys']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['deskeys']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['IPper']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$ippermitido."
							</p>
                            </div>
                        </div>
               			
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>



<script>
$("#EditarModal").modal("show");
</script>
   
<?php  
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>