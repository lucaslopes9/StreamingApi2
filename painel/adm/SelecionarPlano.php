<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$id = empty($_POST['id']) ? "" : $_POST['id'];
$id = str_replace("___","][",$id);
$id = "[".$id."]";
$CadUser = InfoUser(4);
$AcessoUser = InfoUser(3);
?>
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <?php
						
						if($id == "[VC]"){
						$ValorCobrado = empty($_SESSION['ValorCobrado']) ? "" : $_SESSION['ValorCobrado'];
                        $ValorCobradoCab = empty($_SESSION['ValorCobradoCab']) ? "" : $_SESSION['ValorCobradoCab'];
												
						//Para Você - Satélite
						if(!empty($ValorCobrado)){
						
						$tipoplano = "N";
						$tipoperfil = "SAT";
						$SQLVc = "SELECT DISTINCT(perfil) FROM planos WHERE CadUser = :CadUser AND tipoplano = :tipoplano AND tipoperfil = :tipoperfil";
						$SQLVc = $painel_geral->prepare($SQLVc);
						$SQLVc->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
						$SQLVc->bindParam(':tipoplano', $tipoplano, PDO::PARAM_STR);
						$SQLVc->bindParam(':tipoperfil', $tipoperfil, PDO::PARAM_STR);
						$SQLVc->execute();
						$TotalVC = count($SQLVc->fetchAll());
						
						if($TotalVC > 0){
							
						$SQLVc->execute();
						$i = 1;
						while($LnVC = $SQLVc->fetch()){
							
						$perfil = SelecionarPerfil($LnVC['perfil']);
						$valor = number_format($ValorCobrado, 2, ',', '');
						
                        echo "<div class=\"PlanoPag".$i." col-md-4\">
                            <div class=\"panel panel-success push-up-20\">
                                <div class=\"panel-body panel-body-pricing\">
                                    <h2 style=\"font-size:32px; font-weight:bold;\"><center>".$_TRA['paravc']."<br/><small style=\"font-size:25px;\">".VerRepDin()." <span id=\"StatusValor".$i."\">".$valor."</span></small></center></h2>
									<p><center><span style=\"font-size:18px;\">30 ".$_TRA['dias']."</span></center></p>
									<p class=\"text-muted\"><center>".$perfil."</center></p>
                                    <p class=\"text-muted\">
									<div class=\"form-group\">
                        				<label class=\"col-md-3 control-label\">".$_TRA['conexao']."</label>
                            			<div class=\"col-md-9\">
                                			<input type=\"text\" name=\"conexao\" id=\"conexao\" class=\"form-control spinner_default".$i."\" value=\"1\" disabled=\"disabled\"/>
                                		</div>
                       				</div>
									</p>
                                </div>
                                ".SelecionarFormas($LnVC['perfil'], 'S', $i, 'SAT')."
                            </div>
                        </div>";
						
						echo "
						<script>
						$(function(){
        					$(\".spinner_default".$i."\").spinner({
								min: 1,
								step: 1, 
								numberFormat: \"n\",
								spin: function( event, ui ) {
					 				var valorcobrado = '".$ValorCobrado."';
					 				var resultado = valorcobrado * ui.value.toString()+',00';
                   					$(\"#StatusValor".$i."\").html(resultado);
                				}
							});   
						});
						</script>
						";
						
						$i++;
						}
						}
						}
						
						//Para Você - Cabo
						if(!empty($ValorCobradoCab)){
													
						$tipoplano = "N";
						$tipoperfil = "CAB";
						$SQLVc = "SELECT DISTINCT(perfil) FROM planos WHERE CadUser = :CadUser AND tipoplano = :tipoplano AND tipoperfil = :tipoperfil";
						$SQLVc = $painel_geral->prepare($SQLVc);
						$SQLVc->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
						$SQLVc->bindParam(':tipoplano', $tipoplano, PDO::PARAM_STR);
						$SQLVc->bindParam(':tipoperfil', $tipoperfil, PDO::PARAM_STR);
						$SQLVc->execute();
						$TotalVC = count($SQLVc->fetchAll());
												
						if($TotalVC > 0){
							
						$SQLVc->execute();
						$i = 1;
						while($LnVC = $SQLVc->fetch()){
							
						$perfil = SelecionarPerfil($LnVC['perfil']);
						$valor = number_format($ValorCobradoCab, 2, ',', '');
						
                        echo "<div class=\"PlanoPagCab".$i." col-md-4\">
                            <div class=\"panel panel-success push-up-20\">
                                <div class=\"panel-body panel-body-pricing\">
                                    <h2 style=\"font-size:32px; font-weight:bold;\"><center>".$_TRA['paravc']."<br/><small style=\"font-size:25px;\">".VerRepDin()." <span id=\"StatusValorCab".$i."\">".$valor."</span></small></center></h2>
									<p><center><span style=\"font-size:18px;\">30 ".$_TRA['dias']."</span></center></p>
									<p class=\"text-muted\"><center>".$perfil."</center></p>
                                    <p class=\"text-muted\">
									<div class=\"form-group\">
                        				<label class=\"col-md-3 control-label\">".$_TRA['conexao']."</label>
                            			<div class=\"col-md-9\">
                                			<input type=\"text\" name=\"conexao\" id=\"conexao\" class=\"form-control spinner_default_cab".$i."\" value=\"1\" disabled=\"disabled\"/>
                                		</div>
                       				</div>
									</p>
                                </div>
                                ".SelecionarFormas($LnVC['perfil'], 'S', $i, 'CAB')."
                            </div>
                        </div>";
						
						echo "
						<script>
						$(function(){
        					$(\".spinner_default_cab".$i."\").spinner({
								min: 1,
								step: 1, 
								numberFormat: \"n\",
								spin: function( event, ui ) {
					 				var valorcobrado = '".$ValorCobradoCab."';
					 				var resultado = valorcobrado * ui.value.toString()+',00';
                   					$(\"#StatusValorCab".$i."\").html(resultado);
                				}
							});   
						});
						</script>
						";
						
						$i++;
						}
						}
						}
						}
						else{
						
						$tipoplano = $AcessoUser == 2 ? "P" : "N";
						$SQL = "SELECT id, nomeplano, perfil, dias, valor, quantidade FROM planos WHERE CadUser = :CadUser AND tipoplano = :tipoplano AND perfil = :perfil";
						$SQL = $painel_geral->prepare($SQL);
						$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
						$SQL->bindParam(':tipoplano', $tipoplano, PDO::PARAM_STR);
						$SQL->bindParam(':perfil', $id, PDO::PARAM_STR);
						$SQL->execute();
						$Total = count($SQL->fetchAll());
						
						if($Total > 0){
							
						$SQL->execute();
						$i = 1;
						while($Ln = $SQL->fetch()){
							
						$perfil = SelecionarPerfil($Ln['perfil']);
						$valor = number_format($Ln['valor'], 2, ',', '');
						$dias = $Ln['dias'];
						$diasS = $dias > 1 ? $_TRA['dias'] : $_TRA['dia'];
														
						$titulo = empty($Ln['nomeplano']) ? $_TRA['normal']." (".$dias." ".$diasS.")" : $Ln['nomeplano'];
							
                        echo "<div class=\"PlanoPag".$i." col-md-4\">
                            <div class=\"panel panel-success push-up-20\">
                                <div class=\"panel-body panel-body-pricing\">
                                    <h2 style=\"font-size:32px; font-weight:bold;\">
									<center>
									<p><center><span style=\"font-size:18px; color:#3fbae4;\">".$titulo."</span></center></p>
									".$dias." ".$diasS."<br/>
									<small style=\"font-size:25px;\">".VerRepDin()." <span id=\"StatusValor".$i."\">".$valor."</span></small>
									</center>
									</h2>";
								
									if($AcessoUser == 2){
									$quantidade = $Ln['quantidade'];
									echo "<span style=\"font-size:20px;\"><center>".$quantidade." ".$_TRA['Login']."</center></span>";
									}
									
									echo "<p class=\"text-muted\"><center>".$perfil."</center></p>";
									
									if( ($AcessoUser == 3) || ($AcessoUser == 4) ){
                                    echo "<p class=\"text-muted\">
									<div class=\"form-group\">
                        				<label class=\"col-md-3 control-label\">".$_TRA['conexao']."</label>
                            			<div class=\"col-md-9\">
                                			<input type=\"text\" name=\"conexao\" id=\"conexao\" class=\"form-control spinner_default".$i."\" value=\"1\" disabled=\"disabled\"/>
                                		</div>
                       				</div>
									</p>";
									}
									
                                echo "</div>
                                ".SelecionarFormas($Ln['id'], 'N', $i, 'SAT')."
                            </div>
                        </div>";
						
						if( ($AcessoUser == 3) || ($AcessoUser == 4) ){
						echo "
						<script>
						$(function(){
        					$(\".spinner_default".$i."\").spinner({
								min: 1,
								step: 1, 
								numberFormat: \"n\",
								spin: function( event, ui ) {
					 				var valorcobrado = '".$Ln['valor']."';
					 				var resultado = valorcobrado * ui.value.toString()+',00';
                   					$(\"#StatusValor".$i."\").html(resultado);
                				}
							});   
						});
						</script>
						";
						}
						
						$i++;
						}
						}	
							
							
						}
                        ?>  
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        

		<div id="StatusGeral"></div>        

        <script type='text/javascript'>  
		function ProcessarCompra(forma, id, tipo, i, sat){
			
			var conexao;
			
			if(sat == "SAT"){
				conexao = $(".PlanoPag"+i+" #conexao").val();
			}
			else if(sat == "CAB"){
				conexao = $(".PlanoPagCab"+i+" #conexao").val();
			}
			
			panel_refresh($(".page-container")); 
				$.post('ProcessarPlano.php', {forma: forma, id: id, tipo: tipo, conexao: conexao}, function(resposta) {
				
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		</script>
        
        
<?php
}else{
	echo Redirecionar('login.php');
}	
?>