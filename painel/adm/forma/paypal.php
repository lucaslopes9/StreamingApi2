<?php
include("../conexao.php");
include_once("../functions.php");
include_once(IdiomaRetorno(1));
global $_TRA;

if( isset($_POST['payment_status']) && isset($_POST['item_number']) ){

		$payment_status = $_POST['payment_status'];
		$item_number = $_POST['item_number'];
	
		$SelecionarDadosMetodo = SelecionarDadosMetodo($item_number);
		$CadUser = $SelecionarDadosMetodo[0];
		$comprador = $SelecionarDadosMetodo[1];
		$dias = $SelecionarDadosMetodo[2];
		$valor = $SelecionarDadosMetodo[3];
		$perfil = $SelecionarDadosMetodo[4];
		$conexao = $SelecionarDadosMetodo[5];
		$PrePago = $SelecionarDadosMetodo[6];
		$Quantidade = $SelecionarDadosMetodo[7];
		
		$SqlCheck = "SELECT id FROM paypal WHERE item_number = :item_number AND payment_status = :payment_status";
		$SqlCheck = $painel_geral->prepare($SqlCheck);
		$SqlCheck->bindParam(':item_number', $item_number, PDO::PARAM_STR);
		$SqlCheck->bindParam(':payment_status', $payment_status, PDO::PARAM_STR);
		$SqlCheck->execute();
		$Total_Check = count($SqlCheck->fetchAll());
	
			if($Total_Check < 1){
				$DataAtual = strtotime(date('Y-m-d'));
				$SQL = "INSERT INTO paypal (
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
				$SQL->bindParam(':payment_status', $payment_status, PDO::PARAM_STR);
				$SQL->bindParam(':item_number', $item_number, PDO::PARAM_STR);
				$SQL->bindParam(':data', $DataAtual, PDO::PARAM_STR);
				$SQL->execute();
			}

		if( ($payment_status == "Completed") && ($Total_Check < 1) ){
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
		
}else{
	echo Redirecionar('index.php');
}
		
?>