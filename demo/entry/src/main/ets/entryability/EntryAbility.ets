import { UIAbility } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';

// 演示应用只装配连接参数页面，不读取宿主应用数据。
export default class EntryAbility extends UIAbility {
  onWindowStageCreate(stage: window.WindowStage): void {
    stage.loadContent('pages/Index');
  }
}
