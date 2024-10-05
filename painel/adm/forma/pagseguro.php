<?php
include("../conexao.php");
include_once("../functions.php");
include_once(IdiomaRetorno(1));
global $_TRA;

if(isset($_POST['notificationType']) && $_POST['notificationType'] == 'transaction'){

$CadUser = base64_decode($_GET['u']);
$DadosPagSeguro = DadosPagSeguro($CadUser);

$email = $DadosPagSeguro[0];
$token = $DadosPagSeguro[1];

$url = 'https://ws.pagseguro.uol.com.br/v2/transactions/notifications/' . $_POST['notificationCode'] . '?email=' . $email . '&token=' . $token;

	$curl = curl_init($url);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    $transaction= curl_exec($curl);
    curl_close($curl);
	
if($transaction == 'Unauthorized'){
	exit;
}
else{	

		$transaction = simplexml_load_string($transaction);
		$id_transacao = $transaction->code;
		$Referencia = $transaction->reference;
		$TipoPagamento = $transaction->paymentMethod->type;
		$StatusTransacao = $transaction->status;
				
		$SelecionarDadosMetodo = SelecionarDadosMetodo($Referencia);
		$CadUser = $SelecionarDadosMetodo[0];
		$comprador = $SelecionarDadosMetodo[1];
		$dias = $SelecionarDadosMetodo[2];
		$valor = $SelecionarDadosMetodo[3];
		$perfil = $SelecionarDadosMetodo[4];
		$conexao = $SelecionarDadosMetodo[5];
		$PrePago = $SelecionarDadosMetodo[6];
		$Quantidade = $SelecionarDadosMetodo[7];
		
		$SqlCheck = "SELECT id FROM pagseguro WHERE Referencia = :Referencia AND StatusTransacao = :StatusTransacao";
		$SqlCheck = $painel_geral->prepare($SqlCheck);
		$SqlCheck->bindParam(':Referencia', $Referencia, PDO::PARAM_STR);
		$SqlCheck->bindParam(':StatusTransacao', $StatusTransacao, PDO::PARAM_STR);
		$SqlCheck->execute();
		$Total_Check = count($SqlCheck->fetchAll());
	
			if( ($Total_Check < 1) && !empty($comprador) && !empty($CadUser) ){
				$DataAtual = strtotime(date('Y-m-d'));
				$SQL = "INSERT INTO pagseguro (
							comprador,
							CadUser,
							TipoPagamento,
							StatusTransacao,
							Referencia,
							data
          				) VALUES (
							:comprador,
							:CadUser,
							:TipoPagamento,
							:StatusTransacao,
							:Referencia,
							:data
						)";
				$SQL = $painel_geral->prepare($SQL);                                  
				$SQL->bindParam(':comprador', $comprador, PDO::PARAM_STR);
				$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
				$SQL->bindParam(':TipoPagamento', $TipoPagamento, PDO::PARAM_STR);
				$SQL->bindParam(':StatusTransacao', $StatusTransacao, PDO::PARAM_STR);
				$SQL->bindParam(':Referencia', $Referencia, PDO::PARAM_STR);
				$SQL->bindParam(':data', $DataAtual, PDO::PARAM_STR);
				$SQL->execute();
			}

		if( ($StatusTransacao == 3) && ($Total_Check < 1) ){
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
}
		
}else{
	echo Redirecionar('index.php');
}
		
?>