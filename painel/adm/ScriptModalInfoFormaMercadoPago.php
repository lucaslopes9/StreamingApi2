<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){
	
$ColunaAcesso = array('PagamentoMercadoPago');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoMercadoPago = $VerificarAcesso[0];

if($PagamentoMercadoPago == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
$CadUser = InfoUser(2);

$SQL = "SELECT id, clientid, clientsecret FROM contamercadopago WHERE CadUser = :CadUser AND id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->bindParam(':id', $id, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['MercadoPago']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['udr']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".UrlAtual()."forma/mercadopago.php?u=".base64_encode($CadUser)."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Credenciais']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							<a target=\"_blank\" href=\"https://www.mercadopago.com/mlb/account/credentials?type=basic\">https://www.mercadopago.com/mlb/account/credentials?type=basic</a>
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['cdi']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							<a target=\"_blank\" href=\"https://www.mercadopago.com.br/ipn-notifications\">https://www.mercadopago.com.br/ipn-notifications</a>
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ClientID']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['clientid']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ClientSecret']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['clientsecret']."
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