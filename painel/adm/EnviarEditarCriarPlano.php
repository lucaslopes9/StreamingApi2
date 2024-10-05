<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPagSeguro = $VerificarAcesso[0];
$PagamentoPayPal = $VerificarAcesso[1];
$PagamentoMercadoPago = $VerificarAcesso[2];
$PagamentoContaBancaria = $VerificarAcesso[3];

if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') ){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$TipodePerfil = (isset($_POST['TipodePerfil'])) ? $_POST['TipodePerfil'] : '';
	$TipodePlano = (isset($_POST['TipodePlano'])) ? $_POST['TipodePlano'] : '';
	$Dias = (isset($_POST['Dias'])) ? $_POST['Dias'] : '';
	$EditarValorCobrado = (isset($_POST['EditarValorCobrado'])) ? ConverterDinheiro($_POST['EditarValorCobrado']) : '';
	$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
	$Quantidade = (isset($_POST['Quantidade'])) ? $_POST['Quantidade'] : '';
	$nomeplano = (isset($_POST['nomeplano'])) ? $_POST['nomeplano'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif( ($TipodePerfil != "SAT") && ($TipodePerfil != "CAB") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['TipodePerfilin'], "danger");
	}
	elseif( ($TipodePlano != "N") && ($TipodePlano != "P") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['TipodePlanoin'], "danger");
	}
	elseif(empty($Dias)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['diaseuco'], "danger");
	}
	elseif(is_numeric($Dias) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['diasdcan'], "danger");
	}
	elseif( empty($EditarValorCobrado) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['valoreuco'], "danger");
	}
	elseif( strlen(str_replace(".","",ConverterDinheiro($EditarValorCobrado))) > 5 ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['valornpcmdq5d'], "danger");
	}
	elseif(is_numeric(str_replace(".","",ConverterDinheiro($EditarValorCobrado))) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['valordcan'], "danger");
	}
	elseif( empty($EditarPerfil) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['sepmup'], "danger");
	}
	elseif( !empty($Quantidade) && (is_numeric($Quantidade) == false) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Quantidadedcan'], "danger");
	}
	else{
		
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	
	$SQL = "UPDATE planos SET
			tipoperfil = :tipoperfil,
			tipoplano = :tipoplano,
			dias = :dias,
			valor = :valor,
			perfil = :perfil,
			quantidade = :quantidade,
			nomeplano = :nomeplano
            WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':tipoperfil', $TipodePerfil, PDO::PARAM_STR); 
	$SQL->bindParam(':tipoplano', $TipodePlano, PDO::PARAM_STR); 
	$SQL->bindParam(':dias', $Dias, PDO::PARAM_STR); 
	$SQL->bindParam(':valor', $EditarValorCobrado, PDO::PARAM_STR); 
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR); 
	$SQL->bindParam(':quantidade', $Quantidade, PDO::PARAM_STR);
	$SQL->bindParam(':nomeplano', $nomeplano, PDO::PARAM_STR);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
		
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=criar-plano");
	}
		
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>