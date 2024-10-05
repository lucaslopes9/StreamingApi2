<?php
header("HTTP/1.1 200 OK");

include("mp.php");
include("../conexao.php");
include_once("../functions.php");
include_once(IdiomaRetorno(1));
global $_TRA;

$CadUser = base64_decode($_GET['u']);

$id_transacao = $_GET['id'];
$topic = $_GET['topic'];
$DadosMercadoPago = DadosMercadoPago($CadUser);

$clientid = $DadosMercadoPago[0];
$clientsecret = $DadosMercadoPago[1];

$mp = new MP($clientid, $clientsecret);
$access_token = $mp->get_access_token();

$url = "https://api.mercadopago.com/collections/notifications/".$id_transacao."?access_token=".urlencode($access_token);
$data = CURLMercadoPago($url);
$json = json_decode($data);
$external_reference = $json->status;

if (!isset($_GET["id"]) || !ctype_digit($_GET["id"])) {
	http_response_code(400);
	return;
}

$payment_info = $mp->get_payment_info($_GET["id"]);

if ( ($payment_info["status"] == 200) || ($external_reference != 404) ) {
	print_r($payment_info["response"]);
	print_r($external_reference);
	print_r(json_encode(200));
	print_r(http_response_code(200));
}
	
	
	$Referencia = $json->collection->external_reference;
	$reason = $json->collection->reason;
	$transaction_amount = $json->collection->transaction_amount;
	$payment_method_id = $json->collection->payment_method_id;
	$status = $json->collection->status;
		
		$SelecionarDadosMetodo = SelecionarDadosMetodo($Referencia);
		$CadUser = $SelecionarDadosMetodo[0];
		$comprador = $SelecionarDadosMetodo[1];
		$dias = $SelecionarDadosMetodo[2];
		$valor = $SelecionarDadosMetodo[3];
		$perfil = $SelecionarDadosMetodo[4];
		$conexao = $SelecionarDadosMetodo[5];
		$PrePago = $SelecionarDadosMetodo[6];
		$Quantidade = $SelecionarDadosMetodo[7];
		
		$SqlCheck = "SELECT id FROM mercadopago WHERE item_number = :item_number AND payment_status = :payment_status";
		$SqlCheck = $painel_geral->prepare($SqlCheck);
		$SqlCheck->bindParam(':item_number', $Referencia, PDO::PARAM_STR);
		$SqlCheck->bindParam(':payment_status', $status, PDO::PARAM_STR);
		$SqlCheck->execute();
		$Total_Check = count($SqlCheck->fetchAll());
	
			if($Total_Check < 1){
				$DataAtual = strtotime(date('Y-m-d'));
				$SQL = "INSERT INTO mercadopago (
							comprador,
							CadUser,
							payment_status,
							item_number,
							data
          				) VALUES (
							:comprador,
							:CadUser,
							:payment_status,
							:item_number,
							:data
						)";
				$SQL = $painel_geral->prepare($SQL);                                  
				$SQL->bindParam(':comprador', $comprador, PDO::PARAM_STR);
				$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
				$SQL->bindParam(':payment_status', $status, PDO::PARAM_STR);
				$SQL->bindParam(':item_number', $Referencia, PDO::PARAM_STR);
				$SQL->bindParam(':data', $DataAtual, PDO::PARAM_STR);
				$SQL->execute();
			}

		if( ($status == "approved") && ($Total_Check < 1) ){
				VerificarTeste($comprador);
				AtualizarRetorno($CadUser, $comprador, $dias, $perfil, $conexao, $PrePago, $Quantidade);
				
				$VerificarEmailUser = VerificarEmailUser($CadUser, 'Renovacao');
				$DadosComprador = DadosComprador($comprador);
				$Email = $DadosComprador[0];
				$Senha = $DadosComprador[1];
				$Nome = $DadosComprador[2];
				$data_premio = $DadosComprador[3];
				
				//Enviar E-mail de Renovação
				if( (!empty($Email)) && ($VerificarEmailUser == false) ) {
					if($PrePago == "S"){
						$Scota = $Quantidade > 1 ? $_TRA['ccotas'] : $_TRA['ccota'];
						$STempo = $dias > 1 ? $_TRA['dias'] : $_TRA['dia'];
						$VcCli = $Quantidade." ".$Scota." (".$dias." ".$STempo.")";
					}
					else{
						$VcCli = date('d/m/Y', $data_premio);
					}
					
					$ArrayEditarPerfil = array();
					$ex = explode('[',$perfil);
					for($i = 1; $i < count($ex); $i++){
						$ArrayEditarPerfil[] = "[".$ex[$i];
					}

				$SelecionarModelo = SelecionarModelo($CadUser, 'Renovacao', $comprador, $Senha, $Nome, $VcCli, $ArrayEditarPerfil);
		
				$bloqueado = "N";
				$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
				$SQLUser = $painel_geral->prepare($SQLUser);
				$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
				$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
				$SQLUser->execute();
				$LnUser = $SQLUser->fetch();
		
				$EnviarEmailSend = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $Email, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
				}
			}
?>