<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){
	
$ColunaAcesso = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPagSeguro = $VerificarAcesso[0];
$PagamentoPayPal = $VerificarAcesso[1];
$PagamentoMercadoPago = $VerificarAcesso[2];
$PagamentoContaBancaria = $VerificarAcesso[3];

if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') ){ 
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
$CadUser = InfoUser(2);

$SQL = "SELECT id, tipoperfil, tipoplano, dias, valor, perfil, quantidade FROM planos WHERE CadUser = :CadUser AND id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->bindParam(':id', $id, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();

$dias = $Ln['dias'];
$sdias = $dias > 1 ? $_TRA['dias'] : $_TRA['dia'];
																		
if($Ln['tipoperfil'] == "SAT"){
	$tipoperfil = $_TRA['satelite'];
}
else{
	$tipoperfil = $_TRA['cabo'];
}

if($Ln['tipoplano'] == "N"){
	$tipoplano = $_TRA['normal'];
}
else{
	$tipoplano = $_TRA['prepago'];
}
									
	$valor = number_format($Ln['valor'], 2, ',', '');
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['CriarPlano']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['TipodePerfil']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$tipoperfil."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['TipodePlano']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$tipoplano."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['TipodePlano']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$tipoplano."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".ucfirst($_TRA['dias'])."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$dias." ".$sdias."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Valor']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".VerRepDin()." ".$valor."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".SelecionarPerfil($Ln['perfil'])."
							</p>
                            </div>
                        </div>";
						
						if(!empty($Ln['quantidade'])){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Quantidade']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['quantidade']."
							</p>
                            </div>
                        </div>";
						}
						
						
						echo "</form>
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